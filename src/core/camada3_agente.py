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

from config import ARQUIVO_PLAYBOOK, ARQUIVO_SFT, ARQUIVO_METRICAS, SLM_MODELO, OLLAMA_URL, OLLAMA_KEEP_ALIVE, ARQUIVO_BLACKLIST

load_dotenv()
logging.basicConfig(level=logging.INFO, format='[Camada3_Agente] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("AgenteSOC")

# =====================================================================
# 1. MODELOS DE DADOS E SCHEMA RÍGIDO (STRUCTURED OUTPUTS)
# =====================================================================
# A ordem das chaves aqui em baixo é o segredo do Chain-of-Thought (CoT)
class Incidente(BaseModel):
    id_alvo: str = Field(..., description="O IP de origem do atacante.")
    padrao_ataque: str = Field(..., description="Os dados extraídos do firewall.")
    dica_rag: str = Field(..., description="A regra da base de conhecimento.")
    
    # Removido o default="". Agora o LLM é OBRIGADO a gerar essas chaves!
    analise_contexto: str = Field(..., description="PASSO 1: Pense em voz alta. Analise o tempo e o espaço da ameaça.")
    justificativa: str = Field(..., description="PASSO 2: Crie uma justificativa técnica curta baseada na análise.")
    veredito: str = Field(..., description="PASSO 3: Apenas 'BLOQUEAR', 'FALSO_POSITIVO' ou 'MONITORAR'.")
    nivel_confianca: str = Field(..., description="PASSO 4: Apenas 'ALTA', 'MEDIA' ou 'BAIXA'.")

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
        self.ARQUIVO_PLAYBOOK = str(ARQUIVO_PLAYBOOK)
        self.ARQUIVO_SFT = str(ARQUIVO_SFT)
        self.ARQUIVO_METRICAS = str(ARQUIVO_METRICAS)
        self.ARQUIVO_BLACKLIST = str(ARQUIVO_BLACKLIST)
        
        self.MODELO = SLM_MODELO 
        self.OLLAMA_URL = OLLAMA_URL
        self.OLLAMA_KEEP_ALIVE = OLLAMA_KEEP_ALIVE
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
            "keep_alive": self.OLLAMA_KEEP_ALIVE,
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
                metricas_ia = {
                    "total_duration": dados_json.get("total_duration", 0) / 1e9,
                    "prompt_eval_count": dados_json.get("prompt_eval_count", 0),
                    "eval_count": dados_json.get("eval_count", 0),
                    "eval_duration": dados_json.get("eval_duration", 0) / 1e9
                }
                return dados_json.get('response', '{}'), prompt_sistema, prompt_usuario, metricas_ia
                
            except requests.exceptions.RequestException as e:
                tentativas += 1
                logger.error(f"Falha de rede (Ollama): {e}. Tentativa {tentativas}...")
                time.sleep(2)
            except json.JSONDecodeError:
                tentativas += 1
                time.sleep(2)
                
        return '{"avaliacoes": []}', prompt_sistema, prompt_usuario, {}

    def executar_mcp_salvar_lote(self, relatorio_triagem_input, num_lote=1, metricas_lote=None, borda_blacklist=None):
        relatorio_processado = RelatorioTriagem()
        dados_sft = []
        
        incidentes_para_ia = []
        mapa_hashes = {}
        mapa_is_red_team = {}  # MATRIZ DE RASTREabilidade CEGA DO RED TEAM
        
        if metricas_lote is None:
            metricas_lote = {}
        metricas_lote["total_incidentes"] = len(relatorio_triagem_input.incidentes)
        metricas_lote["cache_hits"] = 0
        metricas_lote["cache_misses"] = 0

        # ==========================================================
        # 1. TRIAGEM PELO CACHE SEMÂNTICO (AGORA CORRIGIDO)
        # ==========================================================
        for inc in relatorio_triagem_input.incidentes:
            
            # 💡 Garante a rastreabilidade do Red Team tanto para IA Inédita quanto pro Cache!
            mapa_is_red_team[inc.id_alvo] = inc.is_red_team
            
            # CORREÇÃO DEFINITIVA DO CACHE (Evita o colapso de playbooks falsos-positivos)
            # Removemos TODO E QUALQUER número que varia por lote da chave!
            padrao_limpo = re.sub(r'EVENTOS TOTAIS HOJE: \d+ \| ', '', inc.padrao_ataque)
            padrao_limpo = re.sub(r'Taxa atual de [\d.]+ ev/s\.', 'Taxa atual de X ev/s.', padrao_limpo)
            padrao_limpo = re.sub(r'Upload de [\d.]+ Megabytes', 'Upload de X Megabytes', padrao_limpo)
            padrao_limpo = re.sub(r'tocou \d+ IPs', 'tocou X IPs', padrao_limpo)
            
            assinatura = f"{padrao_limpo}|{inc.dica_rag}".encode('utf-8')
            hash_inc = hashlib.md5(assinatura).hexdigest()

            if hash_inc in self.cache_decisoes:
                logger.info(f"⚡ [CACHE HIT] Reciclando veredito para IP {inc.id_alvo}.")
                inc_cache = Incidente.model_validate_json(self.cache_decisoes[hash_inc])
                inc_cache.justificativa = "[CACHE] " + inc_cache.justificativa 
                relatorio_processado.incidentes.append(inc_cache)
                metricas_lote["cache_hits"] += 1
            else:
                inc_dict = {
                    "id_alvo": inc.id_alvo,
                    "padrao_ataque": inc.padrao_ataque,
                    "dica_rag": inc.dica_rag
                }
                incidentes_para_ia.append(inc_dict)
                mapa_hashes[inc.id_alvo] = hash_inc 
                metricas_lote["cache_misses"] += 1

        # ==========================================================
        # 2. INFERÊNCIA EM LOTE E CHAIN-OF-THOUGHT
        # ==========================================================
        TAMANHO_LOTE = 3 
        
        for i in range(0, len(incidentes_para_ia), TAMANHO_LOTE):
            chunk = incidentes_para_ia[i:i + TAMANHO_LOTE]
            logger.info(f"🧠 [BATCH CoT] Raciocinando sobre {len(chunk)} ameaças inéditas simultaneamente...")
            
            resposta_ia_str, prompt_sistema, prompt_usuario, metricas_ia = self._consultar_ia_batch(chunk)
            
            for k, v in metricas_ia.items():
                metricas_lote[k] = metricas_lote.get(k, 0) + v
            
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
        # ⏱️ TELEMETRIA OTIMIZADA: Relógio de I/O do Disco vs Relógio da IA
        t0_io = time.time()
        
        novas_decisoes = []
        for i in relatorio_processado.incidentes:
            d = i.model_dump()
            # 🕵️ Injeção cirúrgica do Teste Duplo-Cego FORA do modelo restrito
            d["is_red_team"] = mapa_is_red_team.get(i.id_alvo, False)
            novas_decisoes.append(d)
            
            # 🛡️ DEFESA ATIVA (IPS) - Se a IA mandar Bloquear, nós isolamos a rede instantaneamente!
            if d.get("veredito") == "BLOQUEAR":
                if borda_blacklist is not None and i.id_alvo not in borda_blacklist:
                    borda_blacklist[i.id_alvo] = time.time()
                    # Persiste assincronamente no background para sobreviver a reboots
                    with open(self.ARQUIVO_BLACKLIST, "a", encoding="utf-8") as bf:
                        bf.write(f"{i.id_alvo}\n")
                
        # ESCALABILIDADE O(1): Usar JSONL puramente assíncrono para o Dashboard!
        if novas_decisoes:
            with open(self.ARQUIVO_PLAYBOOK, "a", encoding="utf-8") as f:
                for d in novas_decisoes:
                    f.write(json.dumps(d, ensure_ascii=False) + "\n")
            
        if dados_sft: 
            with open(self.ARQUIVO_SFT, "a", encoding="utf-8") as f:
                f.writelines(dados_sft)
                
        # ==========================================================
        # 4. SALVAR MÉTRICAS (MÓDULO FLUIDO DE TELEMETRIA)
        # ==========================================================
        tempo_io = round(time.time() - t0_io, 4)
        
        metricas_lote["lote"] = num_lote
        metricas_lote["timestamp"] = datetime.now().isoformat()
        metricas_lote["tempo_io_disco"] = tempo_io
        
        if metricas_lote.get("eval_duration", 0) > 0:
            metricas_lote["tps"] = round(metricas_lote.get("eval_count", 0) / metricas_lote["eval_duration"], 2)
        else:
            metricas_lote["tps"] = 0.0
            
        with open(self.ARQUIVO_METRICAS, "a", encoding="utf-8") as f:
            f.write(json.dumps(metricas_lote, ensure_ascii=False) + "\n")