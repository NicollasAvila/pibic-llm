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
    nivel_confianca: str = ""

class RelatorioTriagem(BaseModel):
    incidentes: List[Incidente] = []

class Camada3AgenteSOC:
    def __init__(self):
        self.ARQUIVO_PLAYBOOK = "resultados/playbook_global.json"
        self.ARQUIVO_SFT = "resultados/fine_tuning_dataset.jsonl"
        
        # === CHAVE VIRADA PARA LOCAL (EDGE SLM) ===
        self.PROVEDOR = "ollama" 
        self.MODELO = "llama3.1" # Certifique-se de que este é o nome do modelo que você tem no Ollama
        
        if self.PROVEDOR == "groq":
            self.cliente_groq = Groq(api_key=os.getenv("GROQ_API_KEY"))
        elif self.PROVEDOR == "ollama":
            self.ollama_url = "http://localhost:11434/api/chat"

    def _consultar_ia(self, prompt_usuario):
        prompt_sistema = """Você é um Analista de Segurança Nível 2 Sênior avaliando anomalias espaço-temporais.
Ferramentas RAG irão sugerir uma ameaça, mas você DEVE ser cético. Avalie a anomalia temporal e espacial criticamente.

DECISÕES:
1. BLOQUEAR: Ameaça real confirmada pelo espaço, tempo ou contexto do firewall.
2. MONITORAR: Comportamento inconclusivo.
3. FALSO_POSITIVO: Tráfego benigno ou erro óbvio do RAG.

DICAS DE CONTEXTO (FIREWALL):
- Preste atenção à Geolocalização do IP atacante (países anômalos explorando regras locais).
- Verifique a Aplicação L7 (ex: ms-ds-smb fazendo burst é crítico, web-crawler pode ser ruído).

NOVO REQUISITO:
Avalie sua própria certeza no campo "nivel_confianca" (responda APENAS com ALTA, MEDIA ou BAIXA).

Responda APENAS no formato JSON."""
        
        if self.PROVEDOR == "groq":
            try:
                chat = self.cliente_groq.chat.completions.create(
                    messages=[
                        {"role": "system", "content": prompt_sistema},
                        {"role": "user", "content": prompt_usuario}
                    ],
                    model=self.MODELO, temperature=0.0, response_format={"type": "json_object"}
                )
                return chat.choices[0].message.content, prompt_sistema
            except Exception as e:
                logger.error(f"Erro Groq: {e}")
                return None, None
                
        elif self.PROVEDOR == "ollama":
            payload = {
                "model": self.MODELO,
                "messages": [
                    {"role": "system", "content": prompt_sistema},
                    {"role": "user", "content": prompt_usuario}
                ],
                "format": "json",
                "stream": False,
                "options": {"temperature": 0.0}
            }
            try:
                response = requests.post(self.ollama_url, json=payload)
                response.raise_for_status()
                resposta_json = response.json()
                return resposta_json["message"]["content"], prompt_sistema
            except Exception as e:
                logger.error(f"Erro Ollama Local: {e}. Verifique se o Ollama está rodando.")
                return None, None

        return None, None

    def executar_mcp_salvar_lote(self, relatorio_triagem_input, num_lote=1):
        relatorio_processado = RelatorioTriagem()
        timestamp_analise = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        dados_sft = []

        for inc in relatorio_triagem_input.incidentes:
            prompt_usuario = (f"Analise o seguinte incidente:\n{{ 'id_alvo': '{inc.id_alvo}', "
                              f"'padrao_ataque': '{inc.padrao_ataque}', 'dica_rag': '{inc.dica_rag}', "
                              f"'veredito': '', 'justificativa': '', 'nivel_confianca': '' }}")
            
            resposta_ia, prompt_sistema = self._consultar_ia(prompt_usuario)
            
            if resposta_ia:
                try:
                    inc_decidido = Incidente.model_validate_json(resposta_ia)
                    
                    # LOOP DE REFLEXION (AUTO-CORREÇÃO)
                    if inc_decidido.nivel_confianca in ["MEDIA", "BAIXA"]:
                        logger.info(f"Confiança {inc_decidido.nivel_confianca} no IP {inc.id_alvo}. Forçando Auto-Correção...")
                        prompt_correcao = (
                            f"Você indicou confiança {inc_decidido.nivel_confianca} na decisão '{inc_decidido.veredito}'. "
                            f"Revise criticamente o ESPAÇO e o TEMPO do ataque: {inc.padrao_ataque}. "
                            f"A dica RAG ({inc.dica_rag}) faz sentido? Se não, altere o veredito para FALSO_POSITIVO. "
                            f"Gere o JSON COMPLETO novamente, preenchendo TODOS os campos do molde abaixo:\n"
                            f"{{ 'id_alvo': '{inc.id_alvo}', 'padrao_ataque': '{inc.padrao_ataque}', "
                            f"'dica_rag': '{inc.dica_rag}', 'veredito': 'SEU_VEREDITO', 'justificativa': 'SUA_JUSTIFICATIVA', 'nivel_confianca': 'ALTA' }}"
                        )
                        resposta_corrigida, _ = self._consultar_ia(prompt_correcao)
                        inc_decidido = Incidente.model_validate_json(resposta_corrigida)
                        inc_decidido.justificativa += " [Refinado via Auto-Correção]"
                        resposta_ia = resposta_corrigida # Atualiza a resposta para o JSONL

                    inc_decidido.justificativa += f" (Por {self.PROVEDOR.upper()})"
                    relatorio_processado.incidentes.append(inc_decidido)
                    
                    linha_sft = {"messages": [
                        {"role": "system", "content": prompt_sistema},
                        {"role": "user", "content": prompt_usuario},
                        {"role": "assistant", "content": resposta_ia}
                    ]}
                    dados_sft.append(json.dumps(linha_sft, ensure_ascii=False) + "\n")
                    
                except ValidationError as e:
                    logger.error(f"JSON Inválido ignorado.")

        decisoes_antigas = []
        if os.path.exists(self.ARQUIVO_PLAYBOOK):
            with open(self.ARQUIVO_PLAYBOOK, "r", encoding="utf-8") as f:
                decisoes_antigas = json.load(f)
                
        with open(self.ARQUIVO_PLAYBOOK, "w", encoding="utf-8") as f:
            json.dump(decisoes_antigas + [i.model_dump() for i in relatorio_processado.incidentes], f, indent=4)
            
        with open(self.ARQUIVO_SFT, "a", encoding="utf-8") as f:
            f.writelines(dados_sft)