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
        self.alvos_dst = set()       # Caractere Espacial: Topologia direta
        self.portas_alvo = defaultdict(int) # Caractere Temporal: Tendência de portas
        self.acoes = defaultdict(int)       # Conta DENY vs ALLOW
        self.total_eventos = 0

class TriagemEspacoTemporal:
    """
    Camada 1: Extração de Caracteres Multimodais (Spatial, Temporal, Spatio-Temporal).
    Processa logs em lotes baseados em quantidade de linhas para proteger a memória RAM.
    """
    def __init__(self):
        # Regex otimizado para extrair as variáveis cruciais do OSSEC/Firewall
        self.padrao_log = re.compile(
            r'^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*ACTION=(\w+).*SRC=(\S+).*DST=(\S+).*DPT=(\d+)'
        )

    def extrair_caracteres_st(self, lote_linhas: list) -> list:
        """
        Recebe um lote fixo (ex: 5000 linhas) e extrai o formato ST-Align.
        """
        grafo_ips = defaultdict(PerfilAtacante)
        
        # 1. LEITURA RÁPIDA (O(n) - Preenche o Grafo na RAM)
        for linha in lote_linhas:
            match = self.padrao_log.search(linha)
            if not match:
                continue
                
            tempo_str, acao, src, dst, dpt = match.groups()
            tempo_obj = datetime.strptime(tempo_str, "%Y-%m-%d %H:%M:%S")
            
            perfil = grafo_ips[src]
            perfil.total_eventos += 1
            perfil.alvos_dst.add(dst)
            perfil.portas_alvo[dpt] += 1
            perfil.acoes[acao.upper()] += 1
            
            # Atualiza a Janela de Tempo (Primeiro e Último evento vistos)
            if not perfil.primeiro_evento or tempo_obj < perfil.primeiro_evento:
                perfil.primeiro_evento = tempo_obj
            if not perfil.ultimo_evento or tempo_obj > perfil.ultimo_evento:
                perfil.ultimo_evento = tempo_obj

        # 2. EXTRAÇÃO DOS CARACTERES (Tempo, Espaço e Spatio-Temporal)
        resumos_st_align = []
        
        for ip_src, perfil in grafo_ips.items():
            # Filtro de Ruído (Noise): Ignora se for só tráfego normal (ALLOW) de baixa frequência
            if perfil.acoes['DENY'] == 0 and perfil.acoes['DROP'] == 0 and perfil.total_eventos < 10:
                continue

            # --- A. Temporal Characters (Trend / Frequência) ---
            delta_t = (perfil.ultimo_evento - perfil.primeiro_evento).total_seconds()
            delta_t = max(1.0, delta_t) # Evita divisão por zero
            
            taxa_por_segundo = perfil.total_eventos / delta_t
            
            if taxa_por_segundo > 5.0:
                char_temporal = f"[TENDÊNCIA: BURST/ALTA] {perfil.total_eventos} eventos em {int(delta_t)}s ({taxa_por_segundo:.1f} ev/s)."
            elif delta_t > 3600:
                char_temporal = f"[TENDÊNCIA: PERÍODO LONGO] Atividade persistente ao longo de {int(delta_t/3600)} horas."
            else:
                char_temporal = f"[TENDÊNCIA: NORMAL] {perfil.total_eventos} eventos isolados."

            # --- B. Spatial Characters (Topologia do Grafo) ---
            qtd_alvos = len(perfil.alvos_dst)
            alvos_str = ", ".join(list(perfil.alvos_dst)[:3])
            if qtd_alvos > 3: alvos_str += " e outros..."
            
            porta_principal = max(perfil.portas_alvo, key=perfil.portas_alvo.get)
            
            if qtd_alvos > 1:
                char_espacial = f"[CONEXÃO DIRETA DISTRIBUÍDA] IP {ip_src} conectou-se a {qtd_alvos} nós distintos ({alvos_str})."
            else:
                char_espacial = f"[CONEXÃO DIRETA ÚNICA] IP {ip_src} focou no nó {alvos_str}."

            # --- C. Spatio-Temporal Characters (Influência) ---
            # Montando a string final para o LLM (O ST-Align)
            resumo_final = (
                f"ST-ALIGN EVENTO | ORIGEM: {ip_src} | "
                f"ESPAÇO: {char_espacial} | "
                f"TEMPO: {char_temporal} | "
                f"INFLUÊNCIA: Foco na porta {porta_principal} com {perfil.acoes['DENY']} bloqueios."
            )
            
            resumos_st_align.append(resumo_final)
            
        return resumos_st_align

# Teste Rápido no VS Code
if __name__ == "__main__":
    triagem = TriagemEspacoTemporal()
    
    # Simulando um lote de 4 linhas lidas do OSSEC
    lote_simulado = [
        "2026-03-04 14:00:00 ACTION=DENY SRC=185.15.1.1 DST=10.0.0.5 DPT=22 MSG=Failed",
        "2026-03-04 14:00:01 ACTION=DENY SRC=185.15.1.1 DST=10.0.0.6 DPT=22 MSG=Failed",
        "2026-03-04 14:00:02 ACTION=DENY SRC=185.15.1.1 DST=10.0.0.7 DPT=22 MSG=Failed",
        "2026-03-04 15:30:00 ACTION=ALLOW SRC=192.168.1.50 DST=8.8.8.8 DPT=53 MSG=DNS"
    ]
    
    resultados = triagem.extrair_caracteres_st(lote_simulado)
    print("--- RESULTADOS DA TRIAGEM ST-ALIGN ---")
    for r in resultados:
        print(r)