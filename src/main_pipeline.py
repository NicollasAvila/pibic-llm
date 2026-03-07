import os
import glob
import time
import logging
from pathlib import Path

from core.camada1_triagem import TriagemEspacoTemporal
from core.camada2_tradutor import TradutorSemanticoRAG # NOVO: Voltamos a importar o RAG
from core.camada3_agente import AgenteSegurancaSLM
from config import DADOS_RAW_DIR

logging.basicConfig(level=logging.INFO, format='\n[%(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("Orquestrador_ST")

def processar_logs_em_blocos(tamanho_bloco=5000):
    logger.info("=== INICIANDO PIPELINE ESPAÇO-TEMPORAL (BATCH READING) ===")
    
    filtro_st = TriagemEspacoTemporal()
    tradutor = TradutorSemanticoRAG() # NOVO: Instanciamos a Camada 2
    agente = AgenteSegurancaSLM(simular_sem_gpu=True) 
    
    arquivos = glob.glob(os.path.join(DADOS_RAW_DIR, "ossec-archive-*.log"))
    if not arquivos:
        arquivos = [os.path.join(DADOS_RAW_DIR, "sample.log")]
        
    arquivo_alvo = arquivos[0]
    nome_arquivo = os.path.basename(arquivo_alvo)
    logger.info(f"A ler o ficheiro: {nome_arquivo} em blocos de {tamanho_bloco} linhas.")

    bloco_atual = []
    contador_blocos = 1
    total_ameacas = 0

    with open(arquivo_alvo, "r", encoding="utf-8") as f:
        for numero_linha, linha in enumerate(f, 1):
            linha = linha.strip()
            if linha:
                bloco_atual.append(linha)
            
            if len(bloco_atual) >= tamanho_bloco:
                logger.info(f"\n--- Processando Bloco {contador_blocos} ---")
                
                # CAMADA 1: Triagem
                resumos_st = filtro_st.extrair_caracteres_st(bloco_atual)
                
                if resumos_st:
                    # CAMADA 2: NOVO - Enriquecer os resumos com o FAISS
                    resumos_enriquecidos = [tradutor.enriquecer_st_align(res) for res in resumos_st]
                    
                    texto_para_ia = "\n".join([f"[Ameaça {i+1}] {res}" for i, res in enumerate(resumos_enriquecidos)])
                    
                    # CAMADA 3: IA
                    inicio_ia = time.time()
                    relatorio = agente.gerar_playbook_lote(texto_para_ia)
                    tempo_ia = time.time() - inicio_ia
                    
                    agente.executar_mcp_salvar_lote(relatorio, num_lote=contador_blocos)
                    logger.info(f"-> Bloco {contador_blocos} avaliado em {tempo_ia:.2f}s")
                    
                    total_ameacas += len(resumos_st)
                
                bloco_atual = []
                contador_blocos += 1

        # Processar as linhas restantes no fim do ficheiro
        if len(bloco_atual) > 0:
            resumos_st = filtro_st.extrair_caracteres_st(bloco_atual)
            if resumos_st:
                resumos_enriquecidos = [tradutor.enriquecer_st_align(res) for res in resumos_st] # NOVO
                texto_para_ia = "\n".join([f"[Ameaça {i+1}] {res}" for i, res in enumerate(resumos_enriquecidos)])
                relatorio = agente.gerar_playbook_lote(texto_para_ia)
                agente.executar_mcp_salvar_lote(relatorio, num_lote=contador_blocos)

    logger.info(f"\n=== LEITURA CONCLUÍDA! ===")

if __name__ == "__main__":
    processar_logs_em_blocos(tamanho_bloco=5000)