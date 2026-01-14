import ollama
import json
import time
import os

# Configuração para seu Notebook
MODELO = "llama3.2"  # Modelo leve de 3B parâmetros

def carregar_logs():
    logs = []
    # Verifica se a pasta dados existe
    if not os.path.exists('dados'):
        print("ERRO: Pasta 'dados' não encontrada!")
        return None
        
    # Tenta ler os dois arquivos
    arquivos = ['dados/log1.json', 'dados/log2.json']
    for arquivo in arquivos:
        try:
            with open(arquivo, 'r', encoding='utf-8') as f:
                logs.append(json.load(f))
        except FileNotFoundError:
            print(f"AVISO: Arquivo {arquivo} não encontrado.")
    
    if not logs:
        return None
        
    return json.dumps(logs, indent=2)

def main():
    print("--- INICIANDO GERAÇÃO DE PLAYBOOK (Modo Notebook) ---")
    
    # 1. Carrega os dados
    logs_texto = carregar_logs()
    if not logs_texto:
        return

    # 2. Define o Prompt (Instrução)
    system_prompt = """
    Você é um Analista de SOC Sênior. Sua tarefa é analisar logs de segurança e criar um PLAYBOOK DE RESPOSTA.
    
    Analise os JSONs fornecidos e gere um relatório técnico estritamente neste formato:
    
    IDENTIFICAÇÃO:
    (Resuma o incidente, qual regra disparou e qual máquina foi afetada)
    
    ETAPAS DO ATAQUE:
    (Liste cronologicamente ou logicamente o que o atacante tentou fazer, ex: Execução de PowerShell, Evasão)
    
    AVALIAÇÃO TÉCNICA:
    (Liste os IoCs importantes: IPs, Hashes, Nomes de Arquivos, Usuários)
    
    MITIGAÇÃO:
    (O que fazer para evitar que isso se repita? Ex: Bloqueio de GPO, Whitelist)
    
    CONTENÇÃO:
    (O que fazer AGORA? Ex: Isolar host, matar processo)
    
    Responda em Português do Brasil. Seja direto.
    """

    # 3. Envia para a IA
    print(f"🧠 Carregando modelo '{MODELO}' no Ollama...")
    print("⏳ Gerando resposta (pode levar alguns segundos no notebook)...")
    
    inicio = time.time()
    
    try:
        resposta = ollama.chat(model=MODELO, messages=[
            {'role': 'system', 'content': system_prompt},
            {'role': 'user', 'content': f"Logs do Incidente:\n{logs_texto}"},
        ])
        
        fim = time.time()
        
        # 4. Mostra o resultado
        print("\n" + "="*40)
        print(resposta['message']['content'])
        print("="*40)
        print(f"✅ Concluído em {fim - inicio:.2f} segundos.")
        
    except Exception as e:
        print(f"\n❌ Ocorreu um erro: {e}")
        print("DICA: Verifique se o aplicativo do Ollama está rodando.")

if __name__ == "__main__":
    main()