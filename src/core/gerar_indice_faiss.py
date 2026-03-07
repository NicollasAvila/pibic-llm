import os
import pandas as pd
import faiss
import json
from sentence_transformers import SentenceTransformer

# Caminhos
DIR_ATUAL = os.path.dirname(os.path.abspath(__file__))
ARQUIVO_CSV = os.path.join(DIR_ATUAL, "../../dados/raw/threat_intel_base.csv")
PASTA_VECTOR_DB = os.path.join(DIR_ATUAL, "../../dados/vector_db")

os.makedirs(PASTA_VECTOR_DB, exist_ok=True)

def construir_indice():
    print("[1/3] Carregando a Base de Conhecimento (CSV)...")
    df = pd.read_csv(ARQUIVO_CSV)
    
    # O mini-modelo de Embeddings (pesa só ~90MB na RAM!)
    print("[2/3] Baixando/Carregando modelo de Embeddings (all-MiniLM-L6-v2)...")
    modelo_embedding = SentenceTransformer('all-MiniLM-L6-v2')
    
    # Transforma a coluna 'padrao_ataque' em matrizes matemáticas
    textos_para_vetorizar = df['padrao_ataque'].tolist()
    vetores = modelo_embedding.encode(textos_para_vetorizar, show_progress_bar=True)
    
    print("[3/3] Criando e salvando o Índice FAISS...")
    # Descobre a dimensão do vetor (neste modelo é 384)
    dimensao = vetores.shape[1] 
    
    # Cria o banco de dados FAISS baseado em distância L2 (Euclidiana)
    indice_faiss = faiss.IndexFlatL2(dimensao)
    indice_faiss.add(vetores)
    
    # Salva o arquivo matemático pesado
    faiss.write_index(indice_faiss, os.path.join(PASTA_VECTOR_DB, "base_conhecimento.index"))
    
    # Salva as respostas (Dicas RAG) num JSON leve para consulta rápida
    respostas_rag = df['dica_rag'].tolist()
    with open(os.path.join(PASTA_VECTOR_DB, "respostas_rag.json"), "w", encoding="utf-8") as f:
        json.dump(respostas_rag, f, ensure_ascii=False, indent=4)
        
    print(f"✅ SUCESSO! Índice FAISS salvo em: {PASTA_VECTOR_DB}")

if __name__ == "__main__":
    construir_indice()