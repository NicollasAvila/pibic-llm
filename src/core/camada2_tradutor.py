import re
import os
import json
import logging
import faiss
from sentence_transformers import SentenceTransformer

logger = logging.getLogger("Camada2_RAG")
DIR_ATUAL = os.path.dirname(os.path.abspath(__file__))
PASTA_VECTOR_DB = os.path.join(DIR_ATUAL, "../../dados/vector_db")

class TradutorSemanticoRAG:
    """
    Camada 2: Motor de Inteligência de Ameaças (RAG).
    Lê os Caracteres Multimodais extraídos e anexa o contexto tático (MITRE ATT&CK).
    """
    def __init__(self):
        logger.info("Iniciando Motor RAG (Carregando FAISS)...")
        try:
            self.encoder = SentenceTransformer('all-MiniLM-L6-v2')
            
            caminho_indice = os.path.join(PASTA_VECTOR_DB, "base_conhecimento.index")
            self.indice_faiss = faiss.read_index(caminho_indice)
            
            caminho_respostas = os.path.join(PASTA_VECTOR_DB, "respostas_rag.json")
            with open(caminho_respostas, "r", encoding="utf-8") as f:
                self.respostas_rag = json.load(f)
                
            self.faiss_pronto = True
            logger.info("FAISS e Embeddings carregados com sucesso!")
        except Exception as e:
            logger.error(f"Erro ao carregar o RAG FAISS: {e}. Rode 'gerar_indice_faiss.py' antes.")
            self.faiss_pronto = False

    def buscar_dica_rag(self, action: str, dpt: str, ip_origem: str) -> str:
        """Busca a inteligência mais próxima usando busca semântica vetorial (FAISS)."""
        if not self.faiss_pronto:
            return "Indisponível (Banco Vetorial offline)."
            
        query_busca = f"porta {dpt} {action} {ip_origem}"
        vetor_busca = self.encoder.encode([query_busca])
        
        # O FAISS procura o vizinho mais próximo em milissegundos
        distancias, indices = self.indice_faiss.search(vetor_busca, k=1)
        
        if distancias[0][0] > 1.5: 
            return "Nenhuma ameaça conhecida diretamente correlacionada no banco de dados."
            
        return self.respostas_rag[indices[0][0]]

    def enriquecer_st_align(self, texto_st: str) -> str:
        """
        Lê a string da Camada 1, extrai os parâmetros e anexa a Dica RAG.
        Exemplo de entrada: "ST-ALIGN EVENTO | ORIGEM: 185.1.1.1 | ESPAÇO: ... | INFLUÊNCIA: Foco na porta 22..."
        """
        # Extrai o IP e a Porta usando Regex na string gerada pela Camada 1
        match_ip = re.search(r'ORIGEM:\s*(\S+)', texto_st)
        match_porta = re.search(r'porta\s*(\d+)', texto_st)
        
        ip_origem = match_ip.group(1) if match_ip else "IP_Desconhecido"
        porta = match_porta.group(1) if match_porta else "0"
        
        # Como a Camada 1 já filtrou o ruído, assumimos que as ações aqui são bloqueios (DENY/DROP)
        acao_predominante = "deny" 
        
        # Vai ao banco vetorial buscar o parecer técnico
        dica_rag = self.buscar_dica_rag(action=acao_predominante, dpt=porta, ip_origem=ip_origem)
        
        # Devolve a string original enriquecida com a Dica RAG no final
        resumo_enriquecido = f"{texto_st} | DICA RAG: {dica_rag}"
        
        return resumo_enriquecido