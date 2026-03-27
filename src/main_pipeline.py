import os
import glob
import json
import logging
import re
import time
import threading
import queue

from core.camada1_triagem import TriagemEspacoTemporal
from core.camada2_tradutor import TradutorSemanticoRAG
from core.camada3_agente import Camada3AgenteSOC

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("Orquestrador_SOC")

PASTA_RAW = "dados/raw/"
ARQUIVO_CONTROLE = "resultados/controle_leitura.json"

# === A NOVA FILA DE PRODUÇÃO ===
fila_incidentes = queue.Queue()

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
    os.makedirs("resultados", exist_ok=True)
    with open(ARQUIVO_CONTROLE, "w", encoding="utf-8") as f:
        json.dump(controle, f, indent=4)

# === O CONSUMIDOR (Roda em paralelo o tempo todo) ===
def worker_ia(agente):
    logger.info("[Thread IA] Consumidor iniciado. Aguardando anomalias na fila...")
    while True:
        item = fila_incidentes.get()
        if item is None: 
            break # Sinal para desligar a thread
        
        relatorio, num_lote = item
        logger.info(f"[Thread IA] Puxando Lote {num_lote} da fila... Iniciando inferência no SLM.")
        
        # A IA processa no tempo dela, sem travar o resto do sistema
        agente.executar_mcp_salvar_lote(relatorio, num_lote=num_lote)
        
        logger.info(f"[Thread IA] Lote {num_lote} finalizado e salvo no Playbook!")
        fila_incidentes.task_done() # Avisa a fila que terminou este pacote

# === O PRODUTOR (Lê os logs na velocidade da luz) ===
def executar_pipeline(tamanho_bloco=4500):
    logger.info("=== INICIANDO SOC 24/7 (ARQUITETURA ASSÍNCRONA) ===")

    tradutor = TradutorSemanticoRAG()
    agente = Camada3AgenteSOC()
    triagem = TriagemEspacoTemporal()

    # Liga a Thread da IA em segundo plano (Daemon)
    thread_ia = threading.Thread(target=worker_ia, args=(agente,), daemon=True)
    thread_ia.start()

    arquivos_log = sorted(glob.glob(os.path.join(PASTA_RAW, "ossec-archive-*.log")))
    if not arquivos_log:
        logger.error("Nenhum log encontrado na pasta raw.")
        return

    controle = carregar_controle()
    arquivo_alvo = arquivos_log[0] 

    if controle["arquivo_atual"] != arquivo_alvo:
        controle["arquivo_atual"] = arquivo_alvo
        controle["linha_atual"] = 0

    logger.info(f"Lendo o arquivo: {arquivo_alvo}")
    
    with open(arquivo_alvo, "r", encoding="utf-8", errors="ignore") as f:
        for _ in range(controle["linha_atual"]): 
            f.readline()

        while True:
            linhas_lote = []
            linhas_descartadas_firewall = 0
            
            for _ in range(tamanho_bloco):
                linha = f.readline()
                if not linha: 
                    break 
                
                if re.search(r'action=(drop|deny|reset\-.*)', linha, re.IGNORECASE):
                    linhas_descartadas_firewall += 1
                    continue
                    
                linhas_lote.append(linha)

            total_lidas_neste_bloco = len(linhas_lote) + linhas_descartadas_firewall

            if total_lidas_neste_bloco == 0:
                logger.info("🎉 Fim do log alcançado. Firewall sem tráfego novo.")
                break

            logger.info(f"[Leitor Log] Processando {total_lidas_neste_bloco} linhas... [{linhas_descartadas_firewall} descartes nativos]")
            
            relatorio = triagem.processar_bloco(linhas_lote)
            
            if len(relatorio.incidentes) > 0:
                logger.warning(f"🚨 [Leitor Log] {len(relatorio.incidentes)} anomalias detectadas! Enviando para a Fila da IA.")
                
                for inc in relatorio.incidentes:
                    inc.dica_rag = tradutor.buscar_contexto(inc.padrao_ataque)

                controle["lotes_processados"] += 1
                
                # A MÁGICA ACONTECE AQUI: Em vez de chamar a IA, apenas joga na fila e continua lendo!
                fila_incidentes.put((relatorio, controle["lotes_processados"]))
            else:
                logger.info("[Leitor Log] Tráfego normal.")

            controle["linha_atual"] += total_lidas_neste_bloco
            salvar_controle(controle)
            
            time.sleep(0.1) # Pausa minúscula apenas para não monopolizar a CPU

    logger.info("=== LEITURA DE ARQUIVO CONCLUÍDA ===")
    logger.info("Aguardando a Thread da IA terminar de esvaziar a fila de incidentes...")
    
    # Trava o script aqui até a IA terminar todos os pacotes pendentes na fila
    fila_incidentes.join()
    logger.info("=== SOC FINALIZADO COM SUCESSO. TODAS AS AMEAÇAS JULGADAS. ===")

if __name__ == "__main__":
    executar_pipeline()