import os
import json
import numpy as np
import faiss
import logging
import torch  # NOVO: Importado para checar a disponibilidade da placa de vídeo
from sentence_transformers import SentenceTransformer

logger = logging.getLogger("Camada2_RAG")

class TradutorSemanticoRAG:
    """
    Camada 2: Tradutor Semântico (RAG).
    Conecta as extrações da Camada 1 com as regras do MITRE ATT&CK usando FAISS.
    """
    def __init__(self):
        self.caminho_indice = "dados/vector_db/base_conhecimento.index"
        self.caminho_respostas = "dados/vector_db/respostas_rag.json"
        
        # --- A MÁGICA DA PERFORMANCE AQUI ---
        # Verifica se há aceleração gráfica. Como você usa uma RX 6600, se o PyTorch 
        # estiver configurado com ROCm, ele usará a GPU. Senão, faz fallback seguro pra CPU.
        self.device = 'cuda' if torch.cuda.is_available() else 'cpu'
        logger.info(f"[Camada 2] RAG otimizado inicializando no dispositivo: {self.device.upper()}")
        
        # Carrega o modelo de IA que transforma texto em matemática (Embeddings) na GPU/CPU
        self.modelo_embedding = SentenceTransformer('all-MiniLM-L6-v2', device=self.device)
        
        # Carrega o "Cérebro" do FAISS
        if not os.path.exists(self.caminho_indice):
            raise FileNotFoundError(f"Índice FAISS não encontrado em: {self.caminho_indice}. Rode gerar_indice_faiss.py primeiro.")
        self.indice_faiss = faiss.read_index(self.caminho_indice)
        
        # Carrega o "Dicionário" de respostas MITRE
        if not os.path.exists(self.caminho_respostas):
            raise FileNotFoundError(f"Respostas RAG não encontradas em: {self.caminho_respostas}.")
        with open(self.caminho_respostas, "r", encoding="utf-8") as f:
            self.respostas = json.load(f)

    def buscar_contexto(self, texto_padrao: str) -> str:
        try:
            # 1. Transforma a anomalia em vetor
            vetor_busca = self.modelo_embedding.encode([texto_padrao])
            
            # 2. Busca os Top-2 mais próximos no FAISS para triangulação de contexto
            k = 2
            distancias, indices = self.indice_faiss.search(vetor_busca, k)
            
            # 3. LÓGICA DE THRESHOLD (Corte L2 Distância)
            # Acima de 1.2 significa "Não tem relação direta. É ruído matemático."
            THRESHOLD_CORTE = 1.2
            
            dicas_encontradas = []
            for i in range(k):
                distancia = distancias[0][i]
                idx_faiss = indices[0][i]
                
                if idx_faiss != -1 and idx_faiss < len(self.respostas):
                    # Só confia se a distância L2 passar na margem de erro
                    if distancia <= THRESHOLD_CORTE:
                        dicas_encontradas.append(self.respostas[idx_faiss])
                        
            # Se nenhuma heurística bater com o tráfego inédito (Proteção Zero-Day)
            if not dicas_encontradas:
                return "RAG ZERO-DAY DETECTADO: Nenhuma regra de ameaça histórica conhecida se alinha a este tráfego. Avalie por conta própria baseado exclusivamente na anomalia de tempo/espaço."
                
            # Retorna todos os contextos Top-K concatenados e formatados
            resultado_final = " | DICA RAG SECUNDÁRIA: ".join(dicas_encontradas)
            logger.debug(f"RAG Encontrou {len(dicas_encontradas)} regras (Menor Dist: {distancias[0][0]:.2f})")
            return resultado_final
                
        except Exception as e:
            logger.error(f"Erro na busca vetorial RAG: {e}")
            return "FALSO POSITIVO: Falha de segurança ao consultar base de conhecimento."