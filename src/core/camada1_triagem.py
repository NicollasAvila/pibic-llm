import os
import re
import json
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

    def to_dict(self):
        """Converte o perfil para um formato que possa ser salvo em JSON."""
        return {
            "primeiro_evento": self.primeiro_evento.strftime("%Y-%m-%d %H:%M:%S") if self.primeiro_evento else None,
            "ultimo_evento": self.ultimo_evento.strftime("%Y-%m-%d %H:%M:%S") if self.ultimo_evento else None,
            "quantidade_alvos": len(self.alvos_dst),
            "alvos_conhecidos": list(self.alvos_dst)[:10], # Salva os 10 primeiros para não explodir o arquivo
            "portas_alvo": dict(self.portas_alvo),
            "acoes_historicas": dict(self.acoes),
            "total_eventos_acumulados": self.total_eventos
        }

class TriagemEspacoTemporal:
    """
    Camada 1: Extração de Caracteres Multimodais com MEMÓRIA DE LONGO PRAZO.
    """
    def __init__(self):
        # A GRANDE MUDANÇA: O Grafo agora é Global e sobrevive entre os lotes
        self.grafo_global = defaultdict(PerfilAtacante)

    def extrair_caracteres_st(self, lote_linhas: list) -> list:
        # Registamos quem apareceu NESTE lote, para só enviar estes à IA
        ips_ativos_neste_lote = set()
        
        # 1. LEITURA E ATUALIZAÇÃO DA MEMÓRIA GLOBAL
        for linha in lote_linhas:
            match_time = re.search(r'generated_time="([^"]+)"', linha)
            match_src = re.search(r'src_ip=([^\s]+)', linha)
            match_dst = re.search(r'dst_ip=([^\s]+)', linha)
            match_dpt = re.search(r'dst_port=(\d+)', linha)
            match_act = re.search(r'action=([a-zA-Z]+)', linha)
            
            if not (match_time and match_src and match_dst and match_dpt and match_act):
                continue
                
            tempo_str = match_time.group(1)
            src = match_src.group(1)
            dst = match_dst.group(1)
            dpt = match_dpt.group(1)
            acao = match_act.group(1).upper()
            
            try:
                tempo_obj = datetime.strptime(tempo_str, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                continue
            
            ips_ativos_neste_lote.add(src)
            
            # Recupera o perfil histórico do IP (ou cria um novo se for a 1ª vez)
            perfil = self.grafo_global[src]
            
            # ACUMULA os dados novos em vez de substituir
            perfil.total_eventos += 1
            perfil.alvos_dst.add(dst)
            perfil.portas_alvo[dpt] += 1
            perfil.acoes[acao] += 1
            
            if not perfil.primeiro_evento or tempo_obj < perfil.primeiro_evento:
                perfil.primeiro_evento = tempo_obj
            if not perfil.ultimo_evento or tempo_obj > perfil.ultimo_evento:
                perfil.ultimo_evento = tempo_obj

        # 2. SALVAR A MEMÓRIA NO DISCO (Registo de Atividades)
        self._salvar_memoria_disco()

        # 3. EXTRAÇÃO DOS CARACTERES (Apenas para quem atacou agora)
        resumos_st_align = []
        
        for ip_src in ips_ativos_neste_lote:
            perfil = self.grafo_global[ip_src]
            
            # Filtro de Ruído Histórico
            if perfil.acoes.get('DENY', 0) == 0 and perfil.acoes.get('DROP', 0) == 0 and perfil.total_eventos < 3:
                continue

            delta_t = (perfil.ultimo_evento - perfil.primeiro_evento).total_seconds()
            delta_t = max(1.0, delta_t) 
            
            taxa_por_segundo = perfil.total_eventos / delta_t
            
            if taxa_por_segundo > 5.0:
                char_temporal = f"[TENDÊNCIA: BURST/ALTA] Histórico de {perfil.total_eventos} eventos em {int(delta_t)}s ({taxa_por_segundo:.1f} ev/s)."
            elif delta_t > 3600:
                char_temporal = f"[TENDÊNCIA: PERÍODO LONGO] Atividade persistente histórica ao longo de {int(delta_t/3600)} horas."
            else:
                char_temporal = f"[TENDÊNCIA: NORMAL] Histórico de {perfil.total_eventos} eventos isolados."

            qtd_alvos = len(perfil.alvos_dst)
            alvos_str = ", ".join(list(perfil.alvos_dst)[:3])
            if qtd_alvos > 3: alvos_str += " e outros..."
            
            porta_principal = max(perfil.portas_alvo, key=perfil.portas_alvo.get)
            
            if qtd_alvos > 1:
                char_espacial = f"[CONEXÃO DIRETA DISTRIBUÍDA] IP {ip_src} conectou-se historicamente a {qtd_alvos} nós ({alvos_str})."
            else:
                char_espacial = f"[CONEXÃO DIRETA ÚNICA] IP {ip_src} tem foco histórico no nó {alvos_str}."

            # O resumo agora reflete o peso de todo o passado do IP
            resumo_final = (
                f"ST-ALIGN EVENTO | ORIGEM: {ip_src} | "
                f"ESPAÇO: {char_espacial} | "
                f"TEMPO: {char_temporal} | "
                f"INFLUÊNCIA: Foco na porta {porta_principal} com {perfil.acoes.get('DENY', 0)} bloqueios e {perfil.acoes.get('ALLOW', 0)} acessos acumulados."
            )
            
            resumos_st_align.append(resumo_final)
            
        return resumos_st_align

    def _salvar_memoria_disco(self):
        """Salva o Grafo Global em um arquivo JSON para auditoria do SOC."""
        os.makedirs("resultados", exist_ok=True)
        caminho_memoria = "resultados/memoria_global_ips.json"
        
        # Converte o Grafo Global num dicionário organizado
        dados_para_salvar = {ip: perfil.to_dict() for ip, perfil in self.grafo_global.items()}
        
        with open(caminho_memoria, "w", encoding="utf-8") as f:
            json.dump(dados_para_salvar, f, indent=4, ensure_ascii=False)