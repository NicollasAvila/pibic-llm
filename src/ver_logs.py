import pandas as pd
import os

# 1. Configura o caminho correto independente de onde você roda
diretorio_atual = os.path.dirname(os.path.abspath(__file__))
caminho_csv = os.path.join(diretorio_atual, "..", "resultados", "relatorio_cientifico_final.csv")

# 2. Configura o Pandas para mostrar o texto inteiro (sem cortar com '...')
pd.set_option('display.max_colwidth', None)

try:
    # 3. Lê o arquivo
    df = pd.read_csv(caminho_csv)
    
    # 4. Pega o veredito do 4º teste (índice 3), que foi o Adversário/Complexo
    raciocinio = df.iloc[3]['Veredito_Agente']
    
    print("\n" + "="*60)
    print("🧠 RACIOCÍNIO DO AGENTE (TESTE 4 - CENÁRIO ADVERSÁRIO)")
    print("="*60)
    print(raciocinio)
    print("="*60 + "\n")
    
except Exception as e:
    print(f"❌ Erro ao ler o arquivo: {e}")