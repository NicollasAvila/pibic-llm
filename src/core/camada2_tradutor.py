import os
import json
import numpy as np
import faiss
import logging
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
        
        # Carrega o modelo de IA que transforma texto em matemática (Embeddings)
        self.modelo_embedding = SentenceTransformer('all-MiniLM-L6-v2')
        
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
        """
        Recebe o comportamento do atacante, converte para vetor e busca a regra da empresa.
        Esta é a função que o Orquestrador estava procurando!
        """
        try:
            # 1. Transforma a anomalia em vetor
            vetor_busca = self.modelo_embedding.encode([texto_padrao])
            
            # 2. Procura no FAISS qual regra mais se assemelha a este vetor (k=1 significa o 1º mais próximo)
            distancias, indices = self.indice_faiss.search(vetor_busca, k=1)
            indice_encontrado = indices[0][0]
            
            # 3. Retorna a regra de segurança correspondente
            if indice_encontrado != -1 and indice_encontrado < len(self.respostas):
                regra_mitre = self.respostas[indice_encontrado]
                logger.debug(f"RAG Encontrou: {regra_mitre}")
                return regra_mitre
            else:
                return "FALSO POSITIVO: Comportamento não mapeado na matriz de risco. Tráfego considerado benigno."
                
        except Exception as e:
            logger.error(f"Erro na busca vetorial RAG: {e}")
            return "FALSO POSITIVO: Falha de segurança ao consultar base de conhecimento."