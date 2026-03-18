import os
import json
import logging
import time
from datetime import datetime
from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel, Field, ValidationError
from typing import List, Optional

load_dotenv()

logging.basicConfig(level=logging.INFO, format='[Juiz_SOC_70B] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger("JuizAuditor")

class AvaliacaoIncidente(BaseModel):
    ip_alvo: str = Field(..., alias="ip")
    decisao_analista: str = Field(..., alias="decisao")
    nota_fidelidade_factual: int = Field(..., ge=0, le=10, alias="fidelidade_factual")
    nota_acuracia_decisao: int = Field(..., ge=0, le=10, alias="acuracia_decisao")
    nota_qualidade_raciocinio: int = Field(..., ge=0, le=10, alias="qualidade_raciocinio")
    nota_adesao_instrucao: int = Field(..., ge=0, le=10, alias="adesao_instrucao")
    parecer_juiz: str
    timestamp_auditoria: Optional[str] = None

class RelatorioAuditoria(BaseModel):
    avaliacoes: List[AvaliacaoIncidente] = []

class JuizAuditorSOC:
    def __init__(self):
        self.ARQUIVO_AUDITORIA_GLOBAL = "resultados/auditoria_global.json"
        self.ARQUIVO_PLAYBOOK_GLOBAL = "resultados/playbook_global.json"
        
        logger.info("Inicializando Juiz Auditor (Modelo: Llama 3.1 70B via Groq)...")
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("Erro: GROQ_API_KEY não encontrada no arquivo .env.")
        self.cliente = Groq(api_key=api_key)
        self.modelo = "llama-3.3-70b-versatile"

    def _consultar_juiz(self, prompt_usuario):
        # AQUI ESTÁ A MÁGICA: Damos o molde exato do JSON para a IA não se perder
        prompt_sistema = """Você é um Auditor Sênior de Segurança da Informação.
Sua função é auditar as decisões tomadas pelo SLM Analista SOC.
Você é RÍGOROSO e DEVE penalizar severamente a invenção de dados (alucinação).

CRITÉRIOS DE AVALIAÇÃO (NOTAS 0 A 10):
1. fidelidade_factual: 0 se o analista inventou dados. 10 se seguiu apenas os fatos.
2. acuracia_decisao: A decisão é tecnicamente correta com base no RAG e no MITRE?
3. qualidade_raciocinio: A justificativa é lógica e baseada em evidências?
4. adesao_instrucao: Respeitou as instruções de sistema?

Você DEVE retornar EXATAMENTE o seguinte formato JSON e nada mais:
{
    "ip": "<escreva o IP aqui>",
    "decisao": "<escreva a decisão tomada aqui>",
    "fidelidade_factual": 10,
    "acuracia_decisao": 10,
    "qualidade_raciocinio": 10,
    "adesao_instrucao": 10,
    "parecer_juiz": "<escreva seu parecer crítico aqui>"
}
"""
        try:
            chat_completion = self.cliente.chat.completions.create(
                messages=[
                    {"role": "system", "content": prompt_sistema},
                    {"role": "user", "content": prompt_usuario}
                ],
                model=self.modelo,
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            return chat_completion.choices[0].message.content
        except Exception as e:
            logger.error(f"Erro ao consultar Groq (Juiz): {e}")
            return None

    def executar_auditoria_acumulada(self):
        logger.info(f"=== [JUIZ] INICIANDO AUDITORIA NO LIVRO-RAZÃO GLOBAL ===")
        
        if not os.path.exists(self.ARQUIVO_PLAYBOOK_GLOBAL):
            logger.error("Playbook Global não encontrado. Execute o orquestrador primeiro.")
            return

        with open(self.ARQUIVO_PLAYBOOK_GLOBAL, "r", encoding="utf-8") as f:
            todas_decisoes = json.load(f)
            
        logger.info(f"Total de {len(todas_decisoes)} decisões acumuladas encontradas no livro-razão.")

        relatorio_auditoria = RelatorioAuditoria()
        timestamp_agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        decisoes_para_auditar = todas_decisoes 

        for inc in decisoes_para_auditar:
            logger.info(f"Auditando decisão para IP: {inc.get('id_alvo', 'Desconhecido')}...")
            
            prompt_usuario = (
                f"Audite a seguinte decisão do SLM Analista SOC:\n\n"
                f"IP ALVO: '{inc.get('id_alvo', '')}'\n"
                f"DADOS DO LOG: '{inc.get('padrao_ataque', '')}'\n"
                f"DICA RAG: '{inc.get('dica_rag', '')}'\n"
                f"DECISÃO DO ANALISTA: '{inc.get('veredito', '')}'\n"
                f"JUSTIFICATIVA DO ANALISTA: '{inc.get('justificativa', '')}'\n\n"
                f"Preencha o JSON com a sua avaliação."
            )
            
            resposta_juiz = self._consultar_juiz(prompt_usuario)
            
            if resposta_juiz:
                try:
                    avaliacao = AvaliacaoIncidente.model_validate_json(resposta_juiz)
                    avaliacao.timestamp_auditoria = timestamp_agora
                    relatorio_auditoria.avaliacoes.append(avaliacao)
                except ValidationError as e:
                    logger.error(f"Juiz gerou JSON inválido: {e}")
            
            # Pausa de 3 segundos para evitar o erro 429 da Groq
            time.sleep(3)

        logger.info(f"Consolidando novas avaliações no histórico Global...")
        
        auditorias_antigas = []
        os.makedirs("resultados", exist_ok=True)
        
        if os.path.exists(self.ARQUIVO_AUDITORIA_GLOBAL):
            try:
                with open(self.ARQUIVO_AUDITORIA_GLOBAL, "r", encoding="utf-8") as f:
                    auditorias_antigas = json.load(f)
                    if not isinstance(auditorias_antigas, list):
                        auditorias_antigas = []
            except Exception:
                auditorias_antigas = []

        novas_avaliacoes = [av.model_dump(by_alias=True) for av in relatorio_auditoria.avaliacoes]
        lista_consolidada = auditorias_antigas + novas_avaliacoes
        
        with open(self.ARQUIVO_AUDITORIA_GLOBAL, "w", encoding="utf-8") as f:
            json.dump(lista_consolidada, f, indent=4, ensure_ascii=False)
            
        logger.info(f"Histórico de Auditoria Global atualizado. Total de avaliações: {len(lista_consolidada)}.")

if __name__ == "__main__":
    juiz = JuizAuditorSOC()
    juiz.executar_auditoria_acumulada()