import os
import glob
import time
import logging
from pathlib import Path

from core.camada1_triagem import TriagemEspacoTemporal
from core.camada2_tradutor import TradutorSemanticoRAG
from core.camada3_agente import AgenteSegurancaSLM
from config import DADOS_RAW_DIR

logging.basicConfig(level=logging.INFO, format='\n[%(asctime)s] %(levelname)s: %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("Orquestrador_ST")

# Adicionamos o parâmetro "max_blocos" para controlar quando parar
def processar_logs_em_blocos(tamanho_bloco=5000, max_blocos=1):
    logger.info("=== INICIANDO PIPELINE ESPAÇO-TEMPORAL (MODO APRESENTAÇÃO) ===")
    
    filtro_st = TriagemEspacoTemporal()
    tradutor = TradutorSemanticoRAG()
    agente = AgenteSegurancaSLM(simular_sem_gpu=False) 
    
    # 1. Busca os arquivos reais do OSSEC novamente
    arquivos = glob.glob(os.path.join(DADOS_RAW_DIR, "ossec-archive-*.log"))
    if not arquivos:
        logger.error("Nenhum arquivo de log encontrado na pasta!")
        return
        
    arquivo_alvo = arquivos[0]
    nome_arquivo = os.path.basename(arquivo_alvo)
    logger.info(f"Lendo arquivo REAL: {nome_arquivo} em blocos de {tamanho_bloco} linhas.")
    logger.info(f"Atenção: O sistema vai avaliar apenas {max_blocos} bloco(s) para a demonstração.")

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
                
                resumos_st = filtro_st.extrair_caracteres_st(bloco_atual)
                
                if resumos_st:
                    resumos_enriquecidos = [tradutor.enriquecer_st_align(res) for res in resumos_st]
                    texto_para_ia = "\n".join([f"[Ameaça {i+1}] {res}" for i, res in enumerate(resumos_enriquecidos)])
                    
                    inicio_ia = time.time()
                    relatorio = agente.gerar_playbook_lote(texto_para_ia)
                    tempo_ia = time.time() - inicio_ia
                    
                    agente.executar_mcp_salvar_lote(relatorio, num_lote=contador_blocos)
                    logger.info(f"-> Bloco {contador_blocos} avaliado pela IA em {tempo_ia:.2f}s")
                    
                    total_ameacas += len(resumos_st)
                
                bloco_atual = []
                
                # --- A MÁGICA DA DEMONSTRAÇÃO ACONTECE AQUI ---
                # Se já avaliamos a quantidade de blocos pedida, paramos de ler o arquivo gigante
                if contador_blocos >= max_blocos:
                    logger.info(f"\n⚠️ Limite de demonstração ({max_blocos} bloco) atingido. Encerrando leitura com sucesso.")
                    break
                    
                contador_blocos += 1

    logger.info(f"\n=== APRESENTAÇÃO CONCLUÍDA! Total de ameaças agrupadas: {total_ameacas} ===")

if __name__ == "__main__":
    # Aqui controlamos a velocidade da apresentação. 
    # Ele vai ler 5000 linhas, gerar 1 relatório genial no JSON e parar sozinho.
    processar_logs_em_blocos(tamanho_bloco=5000, max_blocos=1)