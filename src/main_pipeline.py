import os
import glob
import json
import logging
import re
import time
from core.camada1_triagem import TriagemEspacoTemporal
from core.camada2_tradutor import TradutorSemanticoRAG
from core.camada3_agente import Camada3AgenteSOC

# O Red Team foi desativado para o Stress Test com dados 100% reais.
# from core.simulador_red_team import injetar_ataque_no_lote

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("Orquestrador_SOC")

PASTA_RAW = "dados/raw/"
ARQUIVO_CONTROLE = "resultados/controle_leitura.json"

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

def executar_pipeline(tamanho_bloco=4500):
    logger.info("=== INICIANDO STRESS TEST: CONSUMO CONTÍNUO DO LOG ===")

    tradutor = TradutorSemanticoRAG()
    agente = Camada3AgenteSOC()
    triagem = TriagemEspacoTemporal()

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
    logger.info(f"Avançando para a linha {controle['linha_atual']} (memória salva)...")

    # Abre o ficheiro apenas uma vez e continua a ler até ao fim
    with open(arquivo_alvo, "r", encoding="utf-8", errors="ignore") as f:
        # Pula as linhas já lidas em execuções anteriores
        for _ in range(controle["linha_atual"]): 
            f.readline()

        while True:
            linhas_lote = []
            linhas_descartadas_firewall = 0
            
            # Lê o próximo bloco de 'tamanho_bloco' linhas
            for _ in range(tamanho_bloco):
                linha = f.readline()
                if not linha: 
                    break # Fim do ficheiro alcançado neste bloco
                
                # EARLY-DROP: O Palo Alto usa letras minúsculas (drop, deny, reset-both, reset-server)
                if re.search(r'action=(drop|deny|reset\-.*)', linha, re.IGNORECASE):
                    linhas_descartadas_firewall += 1
                    continue
                    
                linhas_lote.append(linha)

            total_lidas_neste_bloco = len(linhas_lote) + linhas_descartadas_firewall

            if total_lidas_neste_bloco == 0:
                logger.info("🎉 FIM DO ARQUIVO ALCANÇADO! Todo o tráfego foi processado.")
                break

            logger.info(f"Processando bloco... Lidas {total_lidas_neste_bloco} linhas. "
                        f"[{linhas_descartadas_firewall} descartadas nativamente pelo Firewall]")
            
            # Camada 1 analisa as linhas e constrói o Grafo
            relatorio = triagem.processar_bloco(linhas_lote)
            
            if len(relatorio.incidentes) > 0:
                logger.warning(f"🚨 GATILHO ACIONADO! {len(relatorio.incidentes)} anomalias reais enviadas para o SLM.")
                for inc in relatorio.incidentes:
                    inc.dica_rag = tradutor.buscar_contexto(inc.padrao_ataque)

                controle["lotes_processados"] += 1
                agente.executar_mcp_salvar_lote(relatorio, num_lote=controle["lotes_processados"])
            else:
                logger.info("Tráfego 100% normal. SLM mantido em repouso (Economia de Recursos).")

            # Salva o progresso e avança para o próximo bloco do Loop
            controle["linha_atual"] += total_lidas_neste_bloco
            salvar_controle(controle)
            
            # Pausa de 1 segundo para você conseguir ler o terminal e não fritar a CPU
            time.sleep(1)

    logger.info("=== PIPELINE CONTÍNUO FINALIZADO COM SUCESSO. ===")

if __name__ == "__main__":
    executar_pipeline()