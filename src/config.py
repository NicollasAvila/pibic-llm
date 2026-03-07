import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# --- MAPEAMENTO DE PASTAS ---
BASE_DIR = Path(__file__).resolve().parent.parent
DADOS_RAW_DIR = BASE_DIR / "dados" / "raw"
VECTOR_DB_DIR = BASE_DIR / "dados" / "vector_db"
MODELOS_DIR = BASE_DIR / "modelos"
RESULTADOS_DIR = BASE_DIR / "resultados"

# --- CONFIGURAÇÕES DO MOTOR LLAMA.CPP (Otimizado para 16GB RAM) ---
# Substitua pelo nome exato do arquivo GGUF que você baixar
ARQUIVO_MODELO_SLM = MODELOS_DIR / "qwen2.5-1.5b-instruct-q4_k_m.gguf"

LLAMA_CPP_CONFIG = {
    "model_path": str(ARQUIVO_MODELO_SLM),
    "n_ctx": 4096,          # Janela de contexto (Flash Attention)
    "n_threads": 6,         # Núcleos de CPU dedicados
    "n_gpu_layers": -1,     # -1 transfere todas as camadas possíveis para a VRAM (RX 6600)
    "n_batch": 512,         # Tamanho do batching para processamento rápido
    "verbose": False        # Desliga os logs poluídos do C++ no terminal
}

# --- PROMPT DA CAMADA 3 (Otimizado e Enxuto) ---
# Como a Camada 2 já mastiga o log, a IA não precisa mais caçar chaves JSON.
PROMPT_SISTEMA_AGENTE = """
Você é um Agente Autônomo de Cibersegurança (SOC Nível 1).
Sua função é ler um resumo semântico de tráfego de rede (enriquecido com contexto de espaço, tempo e inteligência de ameaças) e gerar um Playbook de Resposta.

REGRA DE OURO:
1. Confie plenamente na 'DICA RAG' (Inteligência Externa). Se a dica indicar que o IP é seguro, classifique como Falso Positivo.
2. Utilize as Tags de Tempo e Topologia para justificar a gravidade.

Retorne ESTRITAMENTE um objeto JSON com esta estrutura:
{
  "analise_contexto": "Sua interpretação rápida do cenário espacial e temporal",
  "ameaca_identificada": "Nome do ataque ou Tráfego Normal",
  "veredito": "BLOQUEAR, MONITORAR ou FALSO_POSITIVO",
  "mitigacao": "Ação recomendada baseada na Dica RAG"
}
"""