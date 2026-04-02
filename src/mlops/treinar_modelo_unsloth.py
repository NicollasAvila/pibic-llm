# ==============================================================================
# PIPELINE DE MLOPS PARA O SOC AUTÔNOMO (PIBIC)
# Script Científico de Fine-Tuning (LoRA) para o Llama 3.2
# ==============================================================================
# LEIA O ARQUIVO `TREINAMENTO_MLOPS.md` PARA O PASSO A PASSO DE COMO RODAR ISSO!
# ==============================================================================

import os
from unsloth import FastLanguageModel
from unsloth.chat_templates import get_chat_template
from datasets import load_dataset
from trl import SFTTrainer
from transformers import TrainingArguments
from unsloth import is_bfloat16_supported

# ------------------------------------------------------------------------------
# 1. PARÂMETROS GERAIS DO PROJETO
# ------------------------------------------------------------------------------
# Nós usamos a versão Instruct padrão pai para destilarmos nosso conhecimento.
MODELO_BASE = "unsloth/Llama-3.2-3B-Instruct" 
TAMANHO_MAX_CONTEXTO = 4096 # O Suficiente para RAG + CoT

# Seu arquivo JSONL mágico gerado lá no pipeline do Sentinel:
ARQUIVO_DATASET = "fine_tuning_dataset.jsonl" 

# ------------------------------------------------------------------------------
# 2. CARREGAMENTO MAGNÉTICO (UNSLOTH 2x MAIS RÁPIDO)
# ------------------------------------------------------------------------------
print(f"🧠 Baixando Base Tátil do Modelo: {MODELO_BASE}...")
model, tokenizer = FastLanguageModel.from_pretrained(
    model_name = MODELO_BASE,
    max_seq_length = TAMANHO_MAX_CONTEXTO,
    dtype = None,           # Auto-detecta: Float16 (Colab) ou Bfloat16 (RTX Modernas)
    load_in_4bit = True,    # Crucial: Permite treinar confortavelmente em VRAM limitada!
)

# ------------------------------------------------------------------------------
# 3. CONECTANDO OS ADAPTADORES NEURAIS (LoRA)
# ------------------------------------------------------------------------------
# Nós não vamos ensinar inglês e gramática de volta para o Llama, ele já sabe. 
# LoRA (Low-Rank Adaptation) vai modificar apenas uma fração do cérebro dele, focando 
# toda a energia neural na sua regra corporativa e no schema JSON estrito.
model = FastLanguageModel.get_peft_model(
    model,
    r = 16, # Tamanho da "esponja" de conhecimento do LoRA
    target_modules = ["q_proj", "k_proj", "v_proj", "o_proj",
                      "gate_proj", "up_proj", "down_proj",],
    lora_alpha = 32,        # MUDANÇA: O dobro do R. Força o modelo a obedecer o JSON e regras SOC.
    lora_dropout = 0,       # Dropout 0 = Aprendizado mais otimizado
    bias = "none",          
    use_gradient_checkpointing = "unsloth", # Magia Unsloth: Poupa Gigabytes de VRAM
    random_state = 3407,
)

# ------------------------------------------------------------------------------
# 4. TRATAMENTO DO DADO (PADRÃO LLAMA 3 INSTRUCT FORMATTING)
# ------------------------------------------------------------------------------
# Nós preparamos o Dataset no Python com a chave "messages". 
# Essa função acorda o Tokenizer do Llama 3 para aplicar aquelas tags "<|start_header_id|>"
tokenizer = get_chat_template(
    tokenizer,
    chat_template = "llama-3", # Formato Estrito do Llama 3 Oficial
)

def formatar_para_llama(exemplos):
    conversas = exemplos["messages"]
    textos = [tokenizer.apply_chat_template(conversa, tokenize=False, add_generation_prompt=False) for conversa in conversas]
    return { "text" : textos }

print("📚 Carregando o seu Conjunto de Dados do Red Team/SOC...")
dataset_cru = load_dataset("json", data_files=ARQUIVO_DATASET, split="train")

# O `map` vai traduzir linha por linha para a língua da máquina
dataset_formatado = dataset_cru.map(formatar_para_llama, batched = True,)

# --- TRAVA ANTI-TRUNCAMENTO (NOVO) ---
print("🧹 Passando a peneira: Removendo logs gigantes para evitar truncamento de JSON...")
def descartar_gigantes(exemplo):
    # Conta os tokens reais da conversa já formatada
    tokens = len(tokenizer(exemplo["text"])["input_ids"])
    # Só deixa passar se for menor que o nosso limite de segurança
    return tokens <= TAMANHO_MAX_CONTEXTO

dataset_limpo = dataset_formatado.filter(descartar_gigantes)
print(f"📉 Sobraram {len(dataset_limpo)} exemplos perfeitos após a filtragem.")
# -------------------------------------

# ------------------------------------------------------------------------------
# 5. O COMBATE DE TREINAMENTO (SUPERVISED FINE-TUNING)
# ------------------------------------------------------------------------------
print("🔥 Iniciando as fornalhas da NVIDIA - Começando o Treinamento!")
treinador = SFTTrainer(
    model = model,
    tokenizer = tokenizer,
    train_dataset = dataset_limpo, # MUDANÇA: Usando o dataset filtrado
    dataset_text_field = "text",
    max_seq_length = TAMANHO_MAX_CONTEXTO,
    dataset_num_proc = 2,
    packing = False, # Manter cada resposta de anomalia isolada no processamento
    args = TrainingArguments(
        per_device_train_batch_size = 2,    # Batches agressivos esmagam a VRAM (2 é seguro)
        gradient_accumulation_steps = 4,    # Matemática pra simular um batch maior de 8
        warmup_steps = 5,                   # Quantidade de passos para 'aquecer' as engrenagens
        num_train_epochs = 2,               # MUDANÇA: Lê o dataset inteiro 2 vezes (Treino Real)
        learning_rate = 2e-4,               # Velocidade da tesoura genética que altera os neurônios
        fp16 = not is_bfloat16_supported(),
        bf16 = is_bfloat16_supported(),
        logging_steps = 1,
        optim = "adamw_8bit",               # Otimizador de Economia de Memória
        weight_decay = 0.01,
        lr_scheduler_type = "linear",
        seed = 3407,
        output_dir = "checkpoints_soc",
    ),
)

historico = treinador.train()

# ------------------------------------------------------------------------------
# 6. EMPACOTAMENTO DA SABEDORIA EM OLLAMA (EXPORTAÇÃO GGUF)
# ------------------------------------------------------------------------------
NOME_EXPORTACAO = "llama-pibic-guard"

print(f"📦 Sucesso! Exportando os Pesos pra Rodar Limpo Sem Python: {NOME_EXPORTACAO}_q4_k_m.gguf")

# O milagre Unsloth 2024: Exporta diretamente mesclado para o formato GGUF (4 bit) 
# Isso gera um arquivo pesando pífios ~2.2 GB!
model.save_pretrained_gguf(NOME_EXPORTACAO, tokenizer, quantization_method = "q4_k_m")

print("=========================================================")
print("✅ TREINAMENTO COMPLETO! 🎉")
print(f"Procure a pasta `{NOME_EXPORTACAO}` no diretório.")
print(f"Baixe o arquivo GGUF para usar com o Ollama no seu motor da Camada 3!")
print("=========================================================")
