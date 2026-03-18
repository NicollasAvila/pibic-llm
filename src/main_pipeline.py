import os
import glob
import json
import logging
from core.camada1_triagem import TriagemEspacoTemporal
from core.camada2_tradutor import TradutorSemanticoRAG
from core.camada3_agente import Camada3AgenteSOC
from core.simulador_red_team import injetar_ataque_no_lote

# ==========================================
# 1. CONFIGURAÇÃO DE LOGS E CAMINHOS
# ==========================================
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("Orquestrador_SOC")

PASTA_RAW = "dados/raw/"
ARQUIVO_CONTROLE = "resultados/controle_leitura.json"
ARQUIVO_PLAYBOOK = "resultados/playbook_global.json"

# ==========================================
# 2. FUNÇÕES DE CONTROLE E BORDA
# ==========================================
def carregar_controle():
    """Lê o 'marca-páginas' de forma segura, resistente a ficheiros corrompidos."""
    padrao = {"arquivo_atual": "", "linha_atual": 0, "lotes_processados": 0}
    if os.path.exists(ARQUIVO_CONTROLE):
        try:
            with open(ARQUIVO_CONTROLE, "r", encoding="utf-8") as f:
                dados = json.load(f)
                # Garante que as chaves existem, se não, usa o padrão
                return {**padrao, **dados}
        except Exception:
            return padrao
    return padrao

def salvar_controle(controle):
    os.makedirs("resultados", exist_ok=True)
    with open(ARQUIVO_CONTROLE, "w", encoding="utf-8") as f:
        json.dump(controle, f, indent=4)

def atualizar_listas_borda():
    """Lê as decisões globais e gera os TXTs para o Firewall e Dashboard."""
    if not os.path.exists(ARQUIVO_PLAYBOOK): 
        return
        
    try:
        with open(ARQUIVO_PLAYBOOK, "r", encoding="utf-8") as f:
            decisoes = json.load(f)
    except Exception:
        return

    bloqueados = set()
    monitorados = set()
    
    for inc in decisoes:
        if inc.get("veredito") == "BLOQUEAR": 
            bloqueados.add(inc.get("id_alvo"))
        elif inc.get("veredito") == "MONITORAR": 
            monitorados.add(inc.get("id_alvo"))

    with open("resultados/blacklist_firewall.txt", "w", encoding="utf-8") as f:
        for ip in bloqueados: 
            f.write(f"iptables -A INPUT -s {ip} -j DROP\n")

    with open("resultados/watchlist_siem.txt", "w", encoding="utf-8") as f:
        for ip in monitorados: 
            f.write(f"Ossec_Monitor: {ip} marcado para quarentena comportamental\n")

# ==========================================
# 3. PIPELINE PRINCIPAL
# ==========================================
def executar_pipeline(tamanho_bloco=4500):
    logger.info("=== INICIANDO PIPELINE SOC (MODO PRODUÇÃO CONTÍNUA) ===")

    logger.info("Inicializando Motor RAG (Carregando FAISS)...")
    tradutor = TradutorSemanticoRAG()
    logger.info("FAISS e Embeddings carregados com sucesso!")

    agente = Camada3AgenteSOC()
    logger.info("Camada 3 inicializada com IA conectada à Groq.")

    triagem = TriagemEspacoTemporal()
    logger.info("Camada 1 (UBA e Baseline) inicializada.")

    arquivos_log = sorted(glob.glob(os.path.join(PASTA_RAW, "ossec-archive-*.log")))
    if not arquivos_log:
        logger.error("Nenhum log de rede encontrado na pasta raw.")
        return

    controle = carregar_controle()
    arquivo_alvo = arquivos_log[0] 

    if controle["arquivo_atual"] != arquivo_alvo:
        controle["arquivo_atual"] = arquivo_alvo
        controle["linha_atual"] = 0

    logger.info(f"Lendo arquivo: {os.path.basename(arquivo_alvo)}")
    logger.info(f"Retomando leitura a partir da linha: {controle['linha_atual']}")

    linhas_lote = []
    with open(arquivo_alvo, "r", encoding="utf-8", errors="ignore") as f:
        for _ in range(controle["linha_atual"]):
            f.readline()

        for _ in range(tamanho_bloco):
            linha = f.readline()
            if not linha:
                break
            linhas_lote.append(linha)

    if not linhas_lote:
        logger.info("Fim do arquivo alcançado. Sem tráfego novo.")
        return

    logger.info(f"Extraídas {len(linhas_lote)} novas linhas reais.")
    
    # Execução das Camadas
    linhas_lote_misto = injetar_ataque_no_lote(linhas_lote, probabilidade_injecao=1.0)
    relatorio = triagem.processar_bloco(linhas_lote_misto)
    logger.info(f"Enviando {len(relatorio.incidentes)} incidentes para o SLM...")

    for inc in relatorio.incidentes:
        inc.dica_rag = tradutor.buscar_contexto(inc.padrao_ataque)

    controle["lotes_processados"] += 1
    agente.executar_mcp_salvar_lote(relatorio, num_lote=controle["lotes_processados"])

    atualizar_listas_borda()

    controle["linha_atual"] += len(linhas_lote)
    salvar_controle(controle)
    
    logger.info("=== PIPELINE EXECUTADO COM SUCESSO. ===")

if __name__ == "__main__":
    executar_pipeline()