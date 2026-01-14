import time
import json
from litellm import completion

# 1. Configuração dos Modelos que vamos testar (Devem estar instalados no Ollama)
# O prefixo 'ollama/' avisa o LiteLLM para usar o Ollama local
modelos_para_teste = ["ollama/llama3.1", "ollama/mistral", "ollama/qwen2.5"]

# 2. Carregar os Logs (usando os mesmos arquivos da etapa anterior)
def carregar_logs():
    logs = []
    try:
        with open('dados/log1.json', 'r', encoding='utf-8') as f:
            logs.append(json.load(f))
        with open('dados/log2.json', 'r', encoding='utf-8') as f:
            logs.append(json.load(f))
        return json.dumps(logs, indent=2)
    except FileNotFoundError:
        return "Erro: Arquivos de log não encontrados na pasta 'dados'."

logs_texto = carregar_logs()

# 3. Prompt do Sistema (O Playbook)
system_prompt = """
Atue como um Analista Sênior de SOC. Analise os logs JSON fornecidos e crie um Playbook de Resposta a Incidentes.
Formato Obrigatório:
- IDENTIFICAÇÃO (Resumo do incidente)
- ETAPAS DO ATAQUE (Passo a passo técnico)
- AVALIAÇÃO (IoCs, IPs, Hashes)
- MITIGAÇÃO (Ações preventivas)
- CONTENÇÃO (Ações imediatas)
"""

# 4. Loop de Teste
print(f"=== INICIANDO BATERIA DE TESTES COM {len(modelos_para_teste)} MODELOS ===\n")

for modelo in modelos_para_teste:
    print(f"🔄 Testando modelo: {modelo} ...")
    start_time = time.time()
    
    try:
        response = completion(
            model=modelo, 
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": f"Logs para análise:\n{logs_texto}"}
            ],
            api_base="http://localhost:11434" # Endereço padrão do Ollama
        )
        
        tempo_total = time.time() - start_time
        conteudo = response.choices[0].message.content
        
        # Salva o resultado em um arquivo texto para ler depois
        nome_arquivo = f"resultado_{modelo.replace('ollama/', '')}.txt"
        with open(nome_arquivo, "w", encoding="utf-8") as f:
            f.write(f"MODELO: {modelo}\n")
            f.write(f"TEMPO: {tempo_total:.2f}s\n")
            f.write("-" * 40 + "\n")
            f.write(conteudo)
            
        print(f"✅ Sucesso! Tempo: {tempo_total:.2f}s. Salvo em {nome_arquivo}\n")
        
    except Exception as e:
        print(f"❌ Erro ao rodar {modelo}: {e}\n")

print("=== FIM DOS TESTES ===")