import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# =====================================================================
# 🧠 1. MOTOR DO AGENTE IA (Ollama REST API)
# =====================================================================
# Llama 3.2 (3B) otimizado para a sua RX 6600
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434/api/generate")

# NOME DO MODELO DO EXPERIMENTO ATUAL (A/B Testing Isolado)
# Por padrão é 'llama3.2', mas você pode colocar 'meu_modelo_finetuned' aqui ou no .env
SLM_MODELO = os.getenv("SLM_MODELO", "analista-SOC")

# =====================================================================
# 📂 2. MAPEAMENTO DE DIRETÓRIOS E ARQUIVOS (Single Source of Truth)
# =====================================================================
BASE_DIR = Path(__file__).resolve().parent.parent

# Pastas Principais
DADOS_RAW_DIR = BASE_DIR / "dados" / "raw"
VECTOR_DB_DIR = BASE_DIR / "dados" / "vector_db"

# Raiz Global de Resultados e Pasta Dinâmica do Modelo (Separação A/B)
RESULTADOS_DIR_ROOT = BASE_DIR / "resultados"
RESULTADOS_DIR = RESULTADOS_DIR_ROOT / SLM_MODELO

# Arquivos de Estado e Persistência Específicos do Modelo (Não se misturam!)
ARQUIVO_PLAYBOOK = RESULTADOS_DIR / "playbook_global.jsonl"
ARQUIVO_SFT = RESULTADOS_DIR / "fine_tuning_dataset.jsonl"
ARQUIVO_MEMORIA = RESULTADOS_DIR / "memoria_global_ips.json"
ARQUIVO_CONTROLE = RESULTADOS_DIR / "controle_leitura.json"
ARQUIVO_METRICAS = RESULTADOS_DIR / "metricas_desempenho.jsonl"
ARQUIVO_AUDITORIA = RESULTADOS_DIR / "auditoria_global.jsonl"

# Listas Globais de Borda (Manuais/Compartilhadas)
ARQUIVO_BLACKLIST = RESULTADOS_DIR_ROOT / "blacklist_firewall.txt"
ARQUIVO_WATCHLIST = RESULTADOS_DIR_ROOT / "watchlist_siem.txt"

# =====================================================================
# ⚙️ 3. REGRAS DO MOTOR DE INGESTÃO 24/7 (Camada 1 e IA)
# =====================================================================
# Configurações de Hardware e Timeout
OLLAMA_TIMEOUT_SEG = 180         # Tempo de paciência do Python para a GPU responder
OLLAMA_KEEP_ALIVE = "15m"        # Mantém o modelo na VRAM entre os ataques
TAMANHO_LOTE_INFERENCIA = 3      # Quantos incidentes a placa de vídeo processa de uma vez

# Parâmetros de Leitura de Disco
TAMANHO_BLOCO_LEITURA = 4500     # Quantas linhas lê de cada vez
LOTES_PARA_CHECKPOINT = 50       # Salva o grafo no disco a cada 50 blocos (Reduz gargalo I/O)

# Parâmetros de Sobrevivência (Garbage Collector)
HORAS_TTL_MEMORIA = 2            # Apaga IPs da memória RAM se ficarem mudos por 2 horas

# Limiares Matemáticos (Matemática da Janela Deslizante)
LIMIAR_BURST_EVS = 5.0           # Acima de 5 eventos/segundo é considerado anómalo
LIMIAR_DISPERSAO = 3             # Tentar aceder a mais de 3 IPs diferentes é suspeito