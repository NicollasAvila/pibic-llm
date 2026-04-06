import os
import glob
import json
import logging
import re
import time
import threading
import queue

# === IMPORTAÇÕES DA NOSSA ARQUITETURA ===
from  config import (
    DADOS_RAW_DIR, 
    ARQUIVO_CONTROLE, 
    TAMANHO_BLOCO_LEITURA
)
from core.camada1_triagem import TriagemEspacoTemporal
from core.camada2_tradutor import TradutorSemanticoRAG
from core.camada3_agente import Camada3AgenteSOC

# Importe o seu script do Red Team (Ajuste o caminho 'tools.' se o arquivo estiver noutra pasta)
try:
    from core.simulador_red_team import injetar_ataque_no_lote
    RED_TEAM_ATIVO = True
except ImportError as e:
    RED_TEAM_ATIVO = False
    print(f"[Aviso] Erro ao carregar Red Team: {e}. Executando sem simulação de ataques.")

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("Orquestrador_SOC")

# === FILA DE PRODUÇÃO ===
fila_incidentes = queue.Queue()

# === REGEX PRÉ-COMPILADO PARA MÁXIMA VELOCIDADE ===
RE_DROP_FIREWALL = re.compile(r'action=(drop|deny|reset\-.*)', re.IGNORECASE)
RE_BUSCA_IP = re.compile(r'src_ip=([^\s]+)')

def carregar_controle():
    padrao = {"arquivo_atual": "", "linha_atual": 0, "lotes_processados": 0}
    if os.path.exists(ARQUIVO_CONTROLE):
        try:
            with open(ARQUIVO_CONTROLE, "r", encoding="utf-8") as f:
                return {**padrao, **json.load(f)}
        except Exception:
            return padrao
    return padrao

def salvar_controle(controle):
    os.makedirs(os.path.dirname(ARQUIVO_CONTROLE), exist_ok=True)
    with open(ARQUIVO_CONTROLE, "w", encoding="utf-8") as f:
        json.dump(controle, f, indent=4)

# === O CONSUMIDOR DA GPU (Camada 3) ===
def worker_ia(agente, borda_blacklist):
    logger.info("🤖 [Thread IA] Consumidor iniciado. Roteamento IPC ativado...")
    while True:
        item = fila_incidentes.get()
        if item is None: 
            break 
        
        relatorio, num_lote, metricas_lote = item
        
        # A IA processa no tempo dela (Batching + Cache + CoT), sem travar a leitura
        # Puxa a referência viva da blacklist para auto-alimentar o IPS!
        agente.executar_mcp_salvar_lote(relatorio, num_lote=num_lote, metricas_lote=metricas_lote, borda_blacklist=borda_blacklist)
        
        logger.info(f"✅ [Thread IA] Lote {num_lote} finalizado e salvo no Playbook!")
        fila_incidentes.task_done()

# === O PRODUTOR (Motor de Ingestão) ===
def executar_pipeline():
    logger.info("=== INICIANDO SOC 24/7 (ARQUITETURA ASSÍNCRONA) ===")

    tradutor = TradutorSemanticoRAG()
    agente = Camada3AgenteSOC()
    triagem = TriagemEspacoTemporal()
    
    # === MEMÓRIA COMPARTILHADA (MÁGICA DO ZERO I/O BOTTLENECK) ===
    # Formato: {"1.2.3.4": 1698273645.1} (IP -> Timestamp do Ban)
    borda_blacklist = {}

    # Liga a Thread da IA em segundo plano (Ela vai alimentar a variável acima)
    thread_ia = threading.Thread(target=worker_ia, args=(agente, borda_blacklist), daemon=True)
    thread_ia.start()

    arquivos_log = sorted(glob.glob(os.path.join(DADOS_RAW_DIR, "ossec-archive-*.log")))
    if not arquivos_log:
        logger.error("Nenhum log encontrado na pasta raw.")
        return

    controle = carregar_controle()
    arquivo_alvo = arquivos_log[0] 

    if controle["arquivo_atual"] != arquivo_alvo:
        controle["arquivo_atual"] = arquivo_alvo
        controle["linha_atual"] = 0

    logger.info(f"📂 Lendo o arquivo: {arquivo_alvo}")
    
    with open(arquivo_alvo, "r", encoding="utf-8", errors="ignore") as f:
        # Avança rapidamente para a linha onde paramos antes
        for _ in range(controle["linha_atual"]): 
            f.readline()

        while True:
            linhas_brutas = []
            
            # 1. Leitura Pura do Disco
            for _ in range(TAMANHO_BLOCO_LEITURA):
                linha = f.readline()
                if not linha: 
                    break 
                linhas_brutas.append(linha)

            total_lidas = len(linhas_brutas)
            if total_lidas == 0:
                logger.info("🎉 Fim do log alcançado. Firewall sem tráfego novo. Aguardando...")
                break # Num cenário real 24/7, trocaríamos 'break' por 'time.sleep(5)' para esperar logs novos

            # 2. Injeção de Caos (Red Team)
            if RED_TEAM_ATIVO:
                # 5% de chance de injetar um ataque brutal neste lote para treinar o modelo
                linhas_mistas = injetar_ataque_no_lote(linhas_brutas, probabilidade_injecao=0.05)
            else:
                linhas_mistas = linhas_brutas

            # ==========================================================
            # 3. FILTRO DE EARLY-DROP (E NOVO IPS ATIVO DA INTELIGÊNCIA)
            # ==========================================================
            linhas_lote = []
            linhas_descartadas_firewall = 0
            linhas_descartadas_ia = 0
            
            # --- GARBAGE COLLECTOR DA BLACKLIST DA IA (TTL de 24 horas) ---
            t_atual = time.time()
            if controle["lotes_processados"] % 10 == 0:
                ips_expirados = [ip for ip, ts in borda_blacklist.items() if (t_atual - ts) > 86400]
                for ip in ips_expirados:
                    del borda_blacklist[ip]

            for linha in linhas_mistas:
                m_src = RE_BUSCA_IP.search(linha)
                src_ip = m_src.group(1) if m_src else None
                
                # A Borda Mágica: Corta o atacante reincidente antes de gastar GPU ou CPU!
                if src_ip and src_ip in borda_blacklist:
                    linhas_descartadas_ia += 1
                    
                # O Equipamento de Firewall Estático (Antigo):
                elif RE_DROP_FIREWALL.search(linha) and "Alerta_RedTeam" not in linha:
                    linhas_descartadas_firewall += 1
                    
                else:
                    linhas_lote.append(linha)

            logger.info(f"📖 [Leitor] Processando lote com {len(linhas_lote)} conexões suspeitas... [🔥 {linhas_descartadas_ia} Cortadas pela IA | 🛡️ {linhas_descartadas_firewall} Antigas de FW]")
            
            # 4. Envia para a Camada 1 (Triagem Espaço-Temporal)
            t0_c1 = time.perf_counter()
            relatorio = triagem.processar_bloco(linhas_lote)
            t1_c1 = time.perf_counter()
            tempo_c1 = t1_c1 - t0_c1
            
            if len(relatorio.incidentes) > 0:
                logger.warning(f"🚨 [Triagem] {len(relatorio.incidentes)} anomalias detectadas! Enviando para a Fila da GPU.")
                
                # Camada 2: Enriquece com o RAG antes de ir para a fila
                t0_c2 = time.perf_counter()
                for inc in relatorio.incidentes:
                    inc.dica_rag = tradutor.buscar_contexto(inc.padrao_ataque)
                t1_c2 = time.perf_counter()
                tempo_c2 = t1_c2 - t0_c2

                controle["lotes_processados"] += 1
                
                metricas_lote = {
                    "tempo_c1_seg": tempo_c1,
                    "tempo_c2_seg": tempo_c2,
                    "linhas_lidas": total_lidas,
                    "drops_firewall": linhas_descartadas_firewall,
                    "drops_ia_ativo": linhas_descartadas_ia # NOVA TELEMETRIA DA DEFESA ATIVA!
                }
                
                # Joga para a fila e volta imediatamente a ler o log!
                fila_incidentes.put((relatorio, controle["lotes_processados"], metricas_lote))
            else:
                logger.info("✅ [Triagem] Tráfego normal.")

            controle["linha_atual"] += total_lidas
            salvar_controle(controle)
            
            time.sleep(0.01) # Pausa micro para evitar lock de CPU

    logger.info("=== LEITURA DE ARQUIVO CONCLUÍDA ===")
    logger.info("Aguardando a Camada 3 (IA) terminar de esvaziar a fila de incidentes pendentes...")
    
    fila_incidentes.join()
    logger.info("=== SOC FINALIZADO COM SUCESSO. TODAS AS AMEAÇAS JULGADAS. ===")

if __name__ == "__main__":
    executar_pipeline()