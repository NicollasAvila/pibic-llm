import re
import logging
from datetime import datetime
from collections import defaultdict

logger = logging.getLogger("Camada1_ST_Triagem")

class PerfilAtacante:
    """Armazena o estado do grafo e do tempo para um IP de origem específico."""
    def __init__(self):
        self.primeiro_evento = None
        self.ultimo_evento = None
        self.alvos_dst = set()       
        self.portas_alvo = defaultdict(int) 
        self.acoes = defaultdict(int)       
        self.total_eventos = 0

class TriagemEspacoTemporal:
    """
    Camada 1: Extração de Caracteres Multimodais.
    Adaptado para ler formatos complexos de Firewalls (como Palo Alto).
    """
    def __init__(self):
        pass

    def extrair_caracteres_st(self, lote_linhas: list) -> list:
        grafo_ips = defaultdict(PerfilAtacante)
        
        # 1. LEITURA FLEXÍVEL (Ignora ruído de Syslog e foca no Palo Alto)
        for linha in lote_linhas:
            # Procura os pares chave=valor independentemente da ordem na linha
            match_time = re.search(r'generated_time="([^"]+)"', linha)
            match_src = re.search(r'src_ip=([^\s]+)', linha)
            match_dst = re.search(r'dst_ip=([^\s]+)', linha)
            match_dpt = re.search(r'dst_port=(\d+)', linha)
            match_act = re.search(r'action=([a-zA-Z]+)', linha)
            
            # Se faltar algum dado essencial (ex: log do cron ou systemd), ignora a linha
            if not (match_time and match_src and match_dst and match_dpt and match_act):
                continue
                
            tempo_str = match_time.group(1) # Ex: "2026/01/19 21:00:00"
            src = match_src.group(1)
            dst = match_dst.group(1)
            dpt = match_dpt.group(1)
            acao = match_act.group(1).upper()
            
            try:
                tempo_obj = datetime.strptime(tempo_str, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                continue
            
            perfil = grafo_ips[src]
            perfil.total_eventos += 1
            perfil.alvos_dst.add(dst)
            perfil.portas_alvo[dpt] += 1
            perfil.acoes[acao] += 1
            
            if not perfil.primeiro_evento or tempo_obj < perfil.primeiro_evento:
                perfil.primeiro_evento = tempo_obj
            if not perfil.ultimo_evento or tempo_obj > perfil.ultimo_evento:
                perfil.ultimo_evento = tempo_obj

        # 2. EXTRAÇÃO DOS CARACTERES
        resumos_st_align = []
        
        for ip_src, perfil in grafo_ips.items():
            # Filtro de Ruído: Reduzido para testar na sua base (exige pelo menos 3 eventos para analisar ALLOWs)
            if perfil.acoes['DENY'] == 0 and perfil.acoes['DROP'] == 0 and perfil.total_eventos < 3:
                continue

            delta_t = (perfil.ultimo_evento - perfil.primeiro_evento).total_seconds()
            delta_t = max(1.0, delta_t) 
            
            taxa_por_segundo = perfil.total_eventos / delta_t
            
            if taxa_por_segundo > 5.0:
                char_temporal = f"[TENDÊNCIA: BURST/ALTA] {perfil.total_eventos} eventos em {int(delta_t)}s ({taxa_por_segundo:.1f} ev/s)."
            elif delta_t > 3600:
                char_temporal = f"[TENDÊNCIA: PERÍODO LONGO] Atividade persistente ao longo de {int(delta_t/3600)} horas."
            else:
                char_temporal = f"[TENDÊNCIA: NORMAL] {perfil.total_eventos} eventos isolados."

            qtd_alvos = len(perfil.alvos_dst)
            alvos_str = ", ".join(list(perfil.alvos_dst)[:3])
            if qtd_alvos > 3: alvos_str += " e outros..."
            
            porta_principal = max(perfil.portas_alvo, key=perfil.portas_alvo.get)
            
            if qtd_alvos > 1:
                char_espacial = f"[CONEXÃO DIRETA DISTRIBUÍDA] IP {ip_src} conectou-se a {qtd_alvos} nós ({alvos_str})."
            else:
                char_espacial = f"[CONEXÃO DIRETA ÚNICA] IP {ip_src} focou no nó {alvos_str}."

            resumo_final = (
                f"ST-ALIGN EVENTO | ORIGEM: {ip_src} | "
                f"ESPAÇO: {char_espacial} | "
                f"TEMPO: {char_temporal} | "
                f"INFLUÊNCIA: Foco na porta {porta_principal} com {perfil.acoes['DENY']} bloqueios e {perfil.acoes['ALLOW']} acessos."
            )
            
            resumos_st_align.append(resumo_final)
            
        return resumos_st_align