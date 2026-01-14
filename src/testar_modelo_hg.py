import ollama
import json
import time
import os
from src.config import PROMPT_PADRAO, MODELO_FAVORITO

# --- CONFIGURAÇÕES ---
# Usa o modelo definido no arquivo de configuração
MODELO_ALVO = MODELO_FAVORITO 
# Arquivo específico que contém o Hash "2d1f6f8a..." para teste de prova real
ARQUIVO_LOG = "dados/log2.json"

def carregar_log():
    if not os.path.exists(ARQUIVO_LOG):
        print(f"❌ Erro crítico: O arquivo '{ARQUIVO_LOG}' não foi encontrado.")
        print("Certifique-se de que a pasta 'dados' existe e contém o 'log2.json'.")
        return None
    
    with open(ARQUIVO_LOG, 'r', encoding='utf-8') as f:
        # Carrega o JSON real
        dados = json.load(f)
    return dados

def main():
    print(f"=== 🛡️  TESTE DE MODELO FINE-TUNED: {MODELO_ALVO} ===")
    print(f"📄 Arquivo de teste: {ARQUIVO_LOG}")
    
    # 1. Carregar os dados
    log_json = carregar_log()
    if not log_json: return

    # Transforma o JSON em texto para a IA ler
    log_texto = json.dumps(log_json, indent=2)
    
    # 2. Definir o Gabarito (O que a IA TEM que achar)
    # Sabemos que no log2.json existe um campo TargetHash começando com isso
    hash_gabarito = "2d1f6f8a" 
    
    print(f"🎯 Desafio: Encontrar o Hash que começa com '{hash_gabarito}'...")
    print("-" * 50)

    # 3. Execução
    inicio = time.time()
    print("⏳ Enviando prompt estruturado (XML)... Aguarde o raciocínio da IA.")
    
    try:
        # AQUI ESTÁ A MUDANÇA PRINCIPAL:
        # Usamos o PROMPT_PADRAO importado e encapsulamos o log nas tags <log_data>
        response = ollama.chat(model=MODELO_ALVO, messages=[
            {
                'role': 'system', 
                'content': PROMPT_PADRAO
            },
            {
                'role': 'user', 
                'content': f"Analise este log de segurança:\n\n<log_data>\n{log_texto}\n</log_data>"
            }
        ])
        
        resultado = response['message']['content']
        tempo = time.time() - inicio
        
        # 4. Exibir Resultado
        print("\n" + "="*20 + " RESPOSTA DA IA " + "="*20)
        print(resultado)
        print("="*54 + "\n")
        
        # 5. Veredito Automático
        print(f"⏱️  Tempo de processamento: {tempo:.2f} segundos")
        
        if hash_gabarito in resultado:
            print("✅ SUCESSO: O modelo encontrou o HASH corretamente!")
        else:
            print("⚠️  FALHA: O modelo NÃO citou o Hash no texto final.")
            print(f"   (Esperado: {hash_gabarito}...)")
            
    except Exception as e:
        print(f"\n❌ Erro ao rodar o modelo: {e}")
        print("Dica: Verifique se o nome do modelo no 'config.py' está igual ao 'ollama list'")

if __name__ == "__main__":
    main()