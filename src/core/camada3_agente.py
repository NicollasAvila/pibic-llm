import os
import json
import logging
import time
import requests
import hashlib
import re  # NOVO: Para a limpeza do Cache
from datetime import datetime
from dotenv import load_dotenv
from pydantic import BaseModel, Field, ValidationError
from typing import List

load_dotenv()
logging.basicConfig(level=logging.INFO, format='[Camada3_Agente] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("AgenteSOC")

# =====================================================================
# 1. MODELOS DE DADOS E SCHEMA RÍGIDO (STRUCTURED OUTPUTS)
# =====================================================================
# A ordem das chaves aqui em baixo é o segredo do Chain-of-Thought (CoT)
class Incidente(BaseModel):
    id_alvo: str = Field(description="O IP de origem do atacante.")
    padrao_ataque: str = Field(description="Os dados extraídos do firewall.")
    dica_rag: str = Field(description="A regra da base de conhecimento.")
    analise_contexto: str = Field(default="", description="PASSO 1: Pense em voz alta. Analise o tempo e o espaço da ameaça.")
    justificativa: str = Field(default="", description="PASSO 2: Crie uma justificativa técnica curta baseada na análise.")
    veredito: str = Field(default="", description="PASSO 3: Apenas 'BLOQUEAR', 'FALSO_POSITIVO' ou 'MONITORAR'.")
    nivel_confianca: str = Field(default="", description="PASSO 4: Apenas 'ALTA', 'MEDIA' ou 'BAIXA'.")

class RelatorioTriagem(BaseModel):
    incidentes: List[Incidente] = []

# Este modelo será injetado DIRETAMENTE na API do Ollama para forçar a estrutura
class BatchIA(BaseModel):
    avaliacoes: List[Incidente]

# =====================================================================
# 2. MOTOR DO AGENTE SOC
# =====================================================================
class Camada3AgenteSOC:
    def __init__(self):
        self.ARQUIVO_PLAYBOOK = "resultados/playbook_global.json"
        self.ARQUIVO_SFT = "resultados/fine_tuning_dataset.jsonl"
        
        self.MODELO = "llama3.2" 
        self.OLLAMA_URL = "http://localhost:11434/api/generate"
        self.cache_decisoes = {} 

    def _consultar_ia_batch(self, lista_incidentes):
        prompt_sistema = """Você é um Analista de SOC Sênior. Sua tarefa é avaliar incidentes usando a Cadeia de Pensamento.

[REGRAS DE DECISÃO ABSOLUTAS]
1. Se o RAG disser FALSO POSITIVO, o veredito é FALSO_POSITIVO.
2. Se o RAG disser CRÍTICO/ALTO, o veredito é BLOQUEAR.
3. Se o RAG mandar MONITORAR, o veredito é MONITORAR.
4. Baseie-se EXCLUSIVAMENTE nos dados. NUNCA invente fatos.

[CADEIA DE PENSAMENTO OBRIGATÓRIA]
Para cada incidente, você deve gerar os dados nesta EXATA ordem:
1. 'analise_contexto': Pense sobre o que está acontecendo (Ex: "O tráfego é normal e a porta 80 é típica de navegação.")
2. 'justificativa': Resuma a sua análise.
3. 'veredito': Dê a sentença.
4. 'nivel_confianca': Dê a confiança (Sempre ALTA se seguir o RAG)."""

        prompt_usuario = json.dumps(lista_incidentes, ensure_ascii=False, indent=2)
        prompt_completo = f"{prompt_sistema}\n\nAnalise estes incidentes e retorne o JSON estrito:\n{prompt_usuario}"

        # MÁGICA 1: Extrai o schema JSON do Pydantic para o Ollama
        schema_json_rigido = BatchIA.model_json_schema()

        payload = {
            "model": self.MODELO,
            "prompt": prompt_completo,
            "stream": False,
            "format": schema_json_rigido,  # MÁGICA 2: O modelo fica travado neste Schema. Zero alucinações.
            "keep_alive": "15m",
            "options": {
                "temperature": 0.0, # Temperatura 0 para ser um robô determinístico
                "num_predict": 1500 # Aumentado para suportar o texto da analise_contexto
            }
        }

        tentativas = 0
        max_tentativas = 3
        
        while tentativas < max_tentativas:
            try:
                resposta = requests.post(self.OLLAMA_URL, json=payload, timeout=180)
                resposta.raise_for_status()
                
                dados_json = resposta.json()
                return dados_json.get('response', '{}'), prompt_sistema, prompt_usuario
                
            except requests.exceptions.RequestException as e:
                tentativas += 1
                logger.error(f"Falha de rede (Ollama): {e}. Tentativa {tentativas}...")
                time.sleep(2)
            except json.JSONDecodeError:
                tentativas += 1
                time.sleep(2)
                
        return '{"avaliacoes": []}', prompt_sistema, prompt_usuario

    def executar_mcp_salvar_lote(self, relatorio_triagem_input, num_lote=1):
        relatorio_processado = RelatorioTriagem()
        dados_sft = []
        
        incidentes_para_ia = []
        mapa_hashes = {}

        # ==========================================================
        # 1. TRIAGEM PELO CACHE SEMÂNTICO (AGORA CORRIGIDO)
        # ==========================================================
        for inc in relatorio_triagem_input.incidentes:
            
            # CORREÇÃO DO BUG: Remove a contagem mutável de eventos da assinatura!
            padrao_limpo = re.sub(r'EVENTOS TOTAIS HOJE: \d+ \| ', '', inc.padrao_ataque)
            
            assinatura = f"{padrao_limpo}|{inc.dica_rag}".encode('utf-8')
            hash_inc = hashlib.md5(assinatura).hexdigest()

            if hash_inc in self.cache_decisoes:
                logger.info(f"⚡ [CACHE HIT] Reciclando veredito para IP {inc.id_alvo}.")
                inc_cache = Incidente.model_validate_json(self.cache_decisoes[hash_inc])
                inc_cache.justificativa = "[CACHE] " + inc_cache.justificativa 
                relatorio_processado.incidentes.append(inc_cache)
            else:
                inc_dict = {
                    "id_alvo": inc.id_alvo,
                    "padrao_ataque": inc.padrao_ataque,
                    "dica_rag": inc.dica_rag
                }
                incidentes_para_ia.append(inc_dict)
                mapa_hashes[inc.id_alvo] = hash_inc 

        # ==========================================================
        # 2. INFERÊNCIA EM LOTE E CHAIN-OF-THOUGHT
        # ==========================================================
        TAMANHO_LOTE = 3 
        
        for i in range(0, len(incidentes_para_ia), TAMANHO_LOTE):
            chunk = incidentes_para_ia[i:i + TAMANHO_LOTE]
            logger.info(f"🧠 [BATCH CoT] Raciocinando sobre {len(chunk)} ameaças inéditas simultaneamente...")
            
            resposta_ia_str, prompt_sistema, prompt_usuario = self._consultar_ia_batch(chunk)
            
            try:
                json_parseado = json.loads(resposta_ia_str)
                lista_avaliacoes = json_parseado.get("avaliacoes", [])
                
                for avaliacao in lista_avaliacoes:
                    inc_decidido = Incidente(**avaliacao)
                    
                    # Salva no Cache
                    hash_deste_incidente = mapa_hashes.get(inc_decidido.id_alvo)
                    if hash_deste_incidente:
                        self.cache_decisoes[hash_deste_incidente] = inc_decidido.model_dump_json()

                    inc_decidido.justificativa += f" (Por {self.MODELO.upper()})"
                    relatorio_processado.incidentes.append(inc_decidido)
                
                # Salva no dataset de treino SFT
                if lista_avaliacoes:
                    linha_sft = {"messages": [
                        {"role": "system", "content": prompt_sistema},
                        {"role": "user", "content": prompt_usuario},
                        {"role": "assistant", "content": resposta_ia_str}
                    ]}
                    dados_sft.append(json.dumps(linha_sft, ensure_ascii=False) + "\n")
                    
            except (json.JSONDecodeError, ValidationError) as e:
                logger.error(f"Falha ao processar o Batch: {e}")

        # ==========================================================
        # 3. SALVAR RESULTADOS
        # ==========================================================
        decisoes_antigas = []
        if os.path.exists(self.ARQUIVO_PLAYBOOK):
            with open(self.ARQUIVO_PLAYBOOK, "r", encoding="utf-8") as f:
                try:
                    decisoes_antigas = json.load(f)
                except json.JSONDecodeError:
                    pass
                
        with open(self.ARQUIVO_PLAYBOOK, "w", encoding="utf-8") as f:
            json.dump(decisoes_antigas + [i.model_dump() for i in relatorio_processado.incidentes], f, indent=4)
            
        if dados_sft: 
            with open(self.ARQUIVO_SFT, "a", encoding="utf-8") as f:
                f.writelines(dados_sft)