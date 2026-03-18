import os
import json
import logging
import time
import requests
from datetime import datetime
from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel, ValidationError
from typing import List

load_dotenv()

logging.basicConfig(level=logging.INFO, format='[Camada3_Agente] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("AgenteSOC")

class Incidente(BaseModel):
    id_alvo: str
    padrao_ataque: str
    dica_rag: str = ""
    veredito: str = ""       
    justificativa: str = ""  

class RelatorioTriagem(BaseModel):
    incidentes: List[Incidente] = []

class Camada3AgenteSOC:
    def __init__(self):
        self.ARQUIVO_PLAYBOOK_GLOBAL = "resultados/playbook_global.json"
        
        # ==========================================
        # 🎛️ PAINEL DE CONTROLE DA INTELIGÊNCIA ARTIFICIAL
        # ==========================================
        # Escolha o provedor: "groq" (API Nuvem) ou "ollama" (Processamento Local)
        self.PROVEDOR = "groq"
        
        # Escolha o modelo exato que deseja usar:
        # - Se PROVEDOR="groq" -> use "llama-3.1-8b-instant"
        # - Se PROVEDOR="ollama" -> use "llama3.2", "pibic-cyber", "mistral", etc.
        self.MODELO = "llama-3.1-8b-instant"
        # ==========================================
        
        logger.info(f"Inicializando Agente SOC (Provedor: {self.PROVEDOR.upper()} | Modelo: {self.MODELO})...")
        
        if self.PROVEDOR == "groq":
            api_key = os.getenv("GROQ_API_KEY")
            if not api_key:
                raise ValueError("Erro: GROQ_API_KEY não encontrada no arquivo .env.")
            self.cliente_groq = Groq(api_key=api_key)
            
        elif self.PROVEDOR == "ollama":
            self.ollama_url = "http://localhost:11434/api/generate"
            try:
                requests.get("http://localhost:11434/")
            except requests.exceptions.ConnectionError:
                logger.error("ERRO: Servidor Ollama não está rodando!")

    def _consultar_ia(self, prompt_usuario):
        prompt_sistema = """Você é um Analista de Segurança Nível 2 (SOC) Sênior.
Sua função é ler os dados do incidente e a Dica RAG e decidir o veredito (veredito) e a justificativa (justificativa).

DECISÕES POSSÍVEIS (SEJA RÍGIDO):
1. BLOQUEAR: Se a Dica RAG indicar ALERTA CRÍTICO ou ALERTA ALTO e o comportamento for anômalo (Burst/Distribuído).
2. MONITORAR: Se a Dica RAG indicar ALERTA MÉDIO (ex: Port Scan) ou se houver anomalias, mas o tráfego for de baixo risco.
3. FALSO_POSITIVO: Se a Dica RAG indicar FALSO POSITIVO ou se o comportamento for 'Normal' na Whitelist Dinâmica.

REGRAS DE OURO:
- NÃO INVENTE DADOS: Use apenas os IPs, portas e frequências que estão explicitamente no prompt.
- FALSO POSITIVO: Priorize essa decisão se o IP for marcado como 'CONFIÁVEL' no prompt.
- Responda APENAS no formato JSON estruturado exigido, sem nenhum texto adicional.
"""
        # --- ROTA DA GROQ ---
        if self.PROVEDOR == "groq":
            try:
                chat_completion = self.cliente_groq.chat.completions.create(
                    messages=[
                        {"role": "system", "content": prompt_sistema},
                        {"role": "user", "content": prompt_usuario}
                    ],
                    model=self.MODELO,
                    temperature=0.0,
                    response_format={"type": "json_object"}
                )
                return chat_completion.choices[0].message.content
            except Exception as e:
                logger.error(f"Erro na API Groq: {e}")
                return None

        # --- ROTA DO OLLAMA ---
        elif self.PROVEDOR == "ollama":
            prompt_completo = f"{prompt_sistema}\n\n{prompt_usuario}"
            payload = {
                "model": self.MODELO,
                "prompt": prompt_completo,
                "format": "json", 
                "stream": False,
                "options": {
                    "temperature": 0.0 
                }
            }
            try:
                resposta = requests.post(self.ollama_url, json=payload)
                resposta.raise_for_status()
                return resposta.json().get("response", "")
            except Exception as e:
                logger.error(f"Erro no Ollama: {e}")
                return None

    def executar_mcp_salvar_lote(self, relatorio_triagem_input, num_lote=1):
        logger.info(f"=== [AGENTE] AVALIANDO {len(relatorio_triagem_input.incidentes)} INCIDENTES VIA {self.PROVEDOR.upper()} ===")
        
        relatorio_processado = RelatorioTriagem()
        timestamp_analise = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        for inc in relatorio_triagem_input.incidentes:
            logger.info(f"Analisando IP: {inc.id_alvo}...")
            
            prompt_usuario = (
                f"Analise o seguinte incidente de segurança e complete o JSON:\n\n"
                f"{{ 'id_alvo': '{inc.id_alvo}', 'padrao_ataque': '{inc.padrao_ataque}', "
                f"'dica_rag': '{inc.dica_rag}', 'veredito': '', 'justificativa': '' }}"
            )
            
            resposta_ia = self._consultar_ia(prompt_usuario)
            
            if resposta_ia:
                try:
                    incidente_decidido = Incidente.model_validate_json(resposta_ia)
                    # Adiciona uma "assinatura" para você saber quem tomou a decisão no Dashboard
                    incidente_decidido.justificativa += f" (Avaliado por {self.PROVEDOR.upper()}[{self.MODELO}] em {timestamp_analise})"
                    relatorio_processado.incidentes.append(incidente_decidido)
                except ValidationError as e:
                    logger.error(f"IA gerou JSON inválido para IP {inc.id_alvo}: {e}")
            else:
                inc.veredito = "FALHA_IA"
                inc.justificativa = f"Erro na conexão com {self.PROVEDOR.upper()} durante a análise em {timestamp_analise}."
                relatorio_processado.incidentes.append(inc)

            # O freio mágico: Só ativa se estivermos usando a API da Groq
            if self.PROVEDOR == "groq":
                time.sleep(5)

        logger.info(f"Consolidando {len(relatorio_processado.incidentes)} novas decisões no Livro-Razão Global...")
        
        decisoes_antigas = []
        os.makedirs("resultados", exist_ok=True)
        
        if os.path.exists(self.ARQUIVO_PLAYBOOK_GLOBAL):
            try:
                with open(self.ARQUIVO_PLAYBOOK_GLOBAL, "r", encoding="utf-8") as f:
                    decisoes_antigas = json.load(f)
                    if not isinstance(decisoes_antigas, list):
                        decisoes_antigas = []
            except Exception:
                decisoes_antigas = []

        novas_decisoes = [inc.model_dump() for inc in relatorio_processado.incidentes]
        lista_consolidada = decisoes_antigas + novas_decisoes
        
        with open(self.ARQUIVO_PLAYBOOK_GLOBAL, "w", encoding="utf-8") as f:
            json.dump(lista_consolidada, f, indent=4, ensure_ascii=False)
            
        logger.info(f"Livro-Razão Global atualizado. Total acumulado: {len(lista_consolidada)}.")