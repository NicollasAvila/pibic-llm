import os
import json
import logging
import time
import requests
import hashlib
import re
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
class Incidente(BaseModel):
    id_alvo: str = Field(..., description="O IP de origem do atacante.")
    padrao_ataque: str = Field(..., description="Os dados extraídos do firewall.")
    dica_rag: str = Field(..., description="A regra da base de conhecimento.")
    
    # Valores default atuam como última linha de defesa, mas o Schema do Ollama fará o trabalho pesado
    analise_contexto: str = Field(default="Análise omitida.", description="PASSO 1: Pense em voz alta. Analise o tempo e o espaço da ameaça.")
    justificativa: str = Field(default="Justificativa omitida.", description="PASSO 2: Crie uma justificativa técnica curta baseada na análise.")
    veredito: str = Field(default="MONITORAR", description="PASSO 3: Apenas 'BLOQUEAR', 'FALSO_POSITIVO' ou 'MONITORAR'.")
    nivel_confianca: str = Field(default="BAIXA", description="PASSO 4: Apenas 'ALTA', 'MEDIA' ou 'BAIXA'.")

class RelatorioTriagem(BaseModel):
    incidentes: List[Incidente] = []

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
        prompt_sistema = """Você é o Aegis, um Analista SOC Nível 3.
Sua tarefa é avaliar incidentes de rede e gerar a cadeia de pensamento.

[REGRAS DE NEGÓCIO ESTRITAS - OVERRIDE DE SEGURANÇA (A TRÍADE)]
1. BLOQUEAR (Matar) - PRIORIDADE MÁXIMA: 
   - Se o tempo indicar [BURST AGUDO] em portas administrativas (ex: 22 SSH, 3389 RDP). Isso é ataque de Força Bruta. O RAG ESTÁ ERRADO se disser que é benigno. Bloqueie imediatamente.
   - Se houver [⚠️ DLP ALERTA] de Upload massivo (>50MB). Isso é Exfiltração de Dados. O RAG ESTÁ ERRADO se disser que é benigno. Bloqueie imediatamente.
2. FALSO POSITIVO (Ignorar): Se o tráfego for focado na porta 80/443 de uma zona de servidores enviando dados rotineiros SEM alertas de DLP ou Burst, e o RAG afirmar "FALSO POSITIVO".
3. MONITORAR (Investigar): Se o IP apresentar [DISPERSÃO ALTA] tocando vários IPs, MAS sem alertas de DLP nem Burst.
4. Fidelidade Factual OBRIGATÓRIA: Leia a Porta exata no log. A Porta 22 é exclusivamente SSH. NUNCA chame a porta 22 de HTTP/HTTPS. Cite os Megabytes (MB) exatos se houver DLP.

[EXEMPLO 1: Força Bruta SSH (BLOQUEAR)]
{
  "avaliacoes": [
    {
      "id_alvo": "177.74.3.212",
      "padrao_ataque": "ST-ALIGN | ORIGEM: 177.74.3.212 | ESPAÇO: [FOCADO] | TEMPO: [BURST AGUDO] Taxa de 80.0 ev/s | FIREWALL: App [ssh]. Porta 22.",
      "dica_rag": "FALSO POSITIVO: Comportamento não mapeado.",
      "analise_contexto": "Log aponta um [BURST AGUDO] extremo de 80 eventos/segundo focado na porta 22 (SSH).",
      "justificativa": "A taxa de 80 ev/s na porta 22 é uma assinatura inegável de Força Bruta SSH. Discordo do RAG, pois o volume temporal anômalo na porta de gestão comprova o ataque malicioso.",
      "veredito": "BLOQUEAR",
      "nivel_confianca": "ALTA"
    }
  ]
}

[EXEMPLO 2: Exfiltração de Dados (BLOQUEAR)]
{
  "avaliacoes": [
    {
      "id_alvo": "177.74.1.128",
      "padrao_ataque": "ST-ALIGN | ORIGEM: 177.74.1.128 | ESPAÇO: [FOCADO] | TEMPO: [TEMPO NORMAL] | [⚠️ DLP ALERTA] Upload de 200.0 Megabytes | FIREWALL: Porta 443.",
      "dica_rag": "FALSO POSITIVO: Tráfego benigno.",
      "analise_contexto": "Conexão focada na porta 443 com alerta crítico de DLP de 200 MB transferidos.",
      "justificativa": "O alerta DLP de 200 MB de upload para um único alvo exterior indica exfiltração de dados camuflada (Canal Oculto). O RAG falhou em classificar a anomalia volumétrica. Bloqueio imediato para estancar o vazamento.",
      "veredito": "BLOQUEAR",
      "nivel_confianca": "ALTA"
    }
  ]
}

[EXEMPLO 3: Tráfego Legítimo de Servidor (FALSO POSITIVO)]
{
  "avaliacoes": [
    {
      "id_alvo": "10.0.3.40",
      "padrao_ataque": "ST-ALIGN | ORIGEM: 10.0.3.40 (DMZ3) | ESPAÇO: [FOCADO] | TEMPO: [TEMPO NORMAL] | FIREWALL: App [web-browsing]. Porta 80.",
      "dica_rag": "FALSO POSITIVO: Comportamento não mapeado. Tráfego benigno.",
      "analise_contexto": "Tráfego focado na porta 80 vindo da DMZ3 com tempo normal, sem anomalias volumétricas ou picos.",
      "justificativa": "Sem anomalias de burst ou alertas de DLP, a comunicação na porta 80 é consistente com operações normais de web. O RAG confirma tratar-se de comportamento benigno.",
      "veredito": "FALSO_POSITIVO",
      "nivel_confianca": "ALTA"
    }
  ]
}

[EXEMPLO 4: Zona Cinzenta / Varredura (MONITORAR)]
{
  "avaliacoes": [
    {
      "id_alvo": "10.0.1.15",
      "padrao_ataque": "ST-ALIGN | ORIGEM: 10.0.1.15 (REDE_INTERNA) | EVENTOS: 45 | ESPAÇO: [DISPERSÃO ALTA] Este IP já escaneou 5 IPs internos | TEMPO: [TEMPO NORMAL] | FIREWALL: App [unknown]. Porta 445.",
      "dica_rag": "Comportamento anômalo. Possível varredura SMB. Sugere-se investigação.",
      "analise_contexto": "IP da REDE_INTERNA apresenta dispersão alta, tocando 5 alvos diferentes na porta 445 (SMB), mas sem tráfego de burst temporal ou alertas de DLP associados.",
      "justificativa": "A movimentação lateral (dispersão em 5 alvos na porta 445) é altamente suspeita de reconhecimento interno. No entanto, a ausência de exfiltração de dados e a ausência de força bruta indicam que um bloqueio imediato pode ser precipitado. A decisão mais prudente é colocar o alvo em quarentena de observação.",
      "veredito": "MONITORAR",
      "nivel_confianca": "MEDIA"
    }
  ]
}

[INSTRUÇÃO PARA O LOTE ATUAL]
Gere as avaliações para o lote fornecido usando a estrutura JSON estrita requerida.
"""

        prompt_usuario_json = json.dumps(lista_incidentes, ensure_ascii=False, indent=2)
        
        prompt_usuario = f"""Abaixo está um Lote de {len(lista_incidentes)} IPs que entraram no seu radar neste segundo.
Retorne um ÚNICO objeto JSON respondendo a todos eles, OBRIGATORIAMENTE contendo a chave root "avaliacoes".

INCIDENTES EM REDE:
{prompt_usuario_json}
"""

        # 🔥 A OPÇÃO NUCLEAR: Structured Outputs (Esquema JSON Forçado)
        # O Ollama será fisicamente impedido de ignorar qualquer uma destas chaves.
        esquema_forcado = {
            "type": "object",
            "properties": {
                "avaliacoes": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "id_alvo": {"type": "string"},
                            "padrao_ataque": {"type": "string"},
                            "dica_rag": {"type": "string"},
                            "analise_contexto": {"type": "string"},
                            "justificativa": {"type": "string"},
                            "veredito": {"type": "string"},
                            "nivel_confianca": {"type": "string"}
                        },
                        "required": [
                            "id_alvo", "padrao_ataque", "dica_rag", 
                            "analise_contexto", "justificativa", "veredito", "nivel_confianca"
                        ]
                    }
                }
            },
            "required": ["avaliacoes"]
        }

        # Payload formatado perfeitamente para a API nativa do Ollama Local
        payload = {
            "model": self.MODELO,
            "system": prompt_sistema,
            "prompt": prompt_usuario,
            "format": esquema_forcado,
            "stream": False,
            "keep_alive": self.OLLAMA_KEEP_ALIVE,
            "options": {
                "temperature": 0.0
            }
        }

        tentativas = 0
        max_tentativas = 3
        while tentativas < max_tentativas:
            try:
                t0_local = time.time()
                
                # Dispara o log para a placa de vídeo local via Ollama
                resposta = requests.post(self.OLLAMA_URL, json=payload, timeout=180)
                resposta.raise_for_status() 
                
                dados = resposta.json()
                texto_resposta = dados.get("response", "")
                
                t_total = time.time() - t0_local
                
                # Conversão do tempo de nanosegundos (Ollama) para segundos
                metricas_ia = {
                    "total_duration": dados.get("total_duration", 0) / 1e9,
                    "prompt_eval_count": dados.get("prompt_eval_count", 0),
                    "eval_count": dados.get("eval_count", 0),
                    "eval_duration": dados.get("eval_duration", 0) / 1e9
                }
                
                return texto_resposta, prompt_sistema, prompt_usuario_json, metricas_ia
                
            except Exception as e:
                tentativas += 1
                logger.error(f"Falha na API Local do Ollama: {e}. Tentativa {tentativas}...")
                time.sleep(2)
                
        return '{"avaliacoes": []}', prompt_sistema, prompt_usuario_json, {}

    def executar_mcp_salvar_lote(self, relatorio_triagem_input, num_lote=1, metricas_lote=None, borda_blacklist=None):
        relatorio_processado = RelatorioTriagem()
        dados_sft = []
        
        incidentes_para_ia = []
        mapa_hashes = {}
        mapa_is_red_team = {}  
        
        if metricas_lote is None:
            metricas_lote = {}
        metricas_lote["total_incidentes"] = len(relatorio_triagem_input.incidentes)
        metricas_lote["cache_hits"] = 0
        metricas_lote["cache_misses"] = 0

        # ==========================================================
        # 1. TRIAGEM PELO CACHE SEMÂNTICO
        # ==========================================================
        for inc in relatorio_triagem_input.incidentes:
            
            mapa_is_red_team[inc.id_alvo] = inc.is_red_team
            
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
                    "dica_rag": inc.dica_rag,
                    # Preenche as lacunas para guiar modelos menores (Skeleton Prompting)
                    "analise_contexto": "",
                    "justificativa": "",
                    "veredito": "",
                    "nivel_confianca": ""
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
                
                mapa_reconstrucao = {inc_dict["id_alvo"]: inc_dict for inc_dict in chunk}
                
                for avaliacao in lista_avaliacoes:
                    ip_recebido = avaliacao.get("id_alvo")
                    input_original = mapa_reconstrucao.get(ip_recebido, {})
                    
                    avaliacao.setdefault("padrao_ataque", input_original.get("padrao_ataque", "N/A"))
                    avaliacao.setdefault("dica_rag", input_original.get("dica_rag", "N/A"))
                    
                    inc_decidido = Incidente(**avaliacao)
                    
                    hash_deste_incidente = mapa_hashes.get(inc_decidido.id_alvo)
                    if hash_deste_incidente:
                        self.cache_decisoes[hash_deste_incidente] = inc_decidido.model_dump_json()

                    inc_decidido.justificativa += f" (Por {self.MODELO.upper()})"
                    relatorio_processado.incidentes.append(inc_decidido)
                
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
        t0_io = time.time()
        
        novas_decisoes = []
        for i in relatorio_processado.incidentes:
            d = i.model_dump()
            d["is_red_team"] = mapa_is_red_team.get(i.id_alvo, False)
            novas_decisoes.append(d)
            
            if d.get("veredito") == "BLOQUEAR":
                if borda_blacklist is not None and i.id_alvo not in borda_blacklist:
                    borda_blacklist[i.id_alvo] = time.time()
                    with open(self.ARQUIVO_BLACKLIST, "a", encoding="utf-8") as bf:
                        bf.write(f"{i.id_alvo}\n")
                
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