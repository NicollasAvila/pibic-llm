import sys
from pathlib import Path

# Descobre o caminho absoluto da pasta 'src' e força no path do Python
caminho_src = str(Path(__file__).resolve().parent.parent)
if caminho_src not in sys.path:
    sys.path.insert(0, caminho_src)

import os
import json
import logging
import time
from datetime import datetime
from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel, Field, ValidationError
from typing import List, Optional

# === IMPORTAÇÃO DA NOSSA ARQUITETURA ===
from config import ARQUIVO_PLAYBOOK, RESULTADOS_DIR

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

class JuizAuditorSOC:
    def __init__(self):
        self.ARQUIVO_PLAYBOOK_GLOBAL = ARQUIVO_PLAYBOOK
        self.ARQUIVO_AUDITORIA_GLOBAL = RESULTADOS_DIR / "auditoria_global.json" 
        
        logger.info("Inicializando Juiz Auditor (Modelo: Llama 3.3 70B via Groq)...")
        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("Erro: GROQ_API_KEY não encontrada no arquivo .env.")
        self.cliente = Groq(api_key=api_key)
        self.modelo = "llama-3.3-70b-versatile"

    def _consultar_juiz(self, prompt_usuario):
        prompt_sistema = """Você é um Auditor Sênior de Segurança da Informação.
Sua função é auditar as decisões tomadas por um Analista SOC (IA Menor).
Você é RIGOROSO e DEVE penalizar severamente a invenção de dados (alucinação).

CRITÉRIOS DE AVALIAÇÃO (NOTAS 0 A 10):
1. fidelidade_factual: 0 se o analista inventou dados. 10 se a análise bater 100% com o log bruto.
2. acuracia_decisao: A decisão final bate com a instrução do RAG?
3. qualidade_raciocinio: A 'analise_contexto' escrita pelo analista tem lógica e suporta o veredito final?
4. adesao_instrucao: Respeitou a regra de nunca inventar informações?

Você DEVE retornar EXATAMENTE o seguinte formato JSON e nada mais:
{
    "ip": "<escreva o IP aqui>",
    "decisao": "<escreva a decisão tomada aqui>",
    "fidelidade_factual": 10,
    "acuracia_decisao": 10,
    "qualidade_raciocinio": 10,
    "adesao_instrucao": 10,
    "parecer_juiz": "<escreva seu parecer crítico em 2 frases>"
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

        # === LEITURA OTIMIZADA DE JSONL (JSON Lines) ===
        todas_decisoes = []
        with open(self.ARQUIVO_PLAYBOOK_GLOBAL, "r", encoding="utf-8") as f:
            for linha in f:
                linha = linha.strip()
                if not linha:  # Ignora linhas em branco
                    continue
                try:
                    # Carrega cada linha como um JSON independente
                    incidente = json.loads(linha)
                    todas_decisoes.append(incidente)
                except json.JSONDecodeError as e:
                    logger.warning(f"Ignorando linha malformada no JSONL: {e}")
        # ===============================================
            
        logger.info(f"Total de {len(todas_decisoes)} decisões acumuladas no Playbook.")

        # --- OTIMIZAÇÃO: EVITA RE-AVALIAR O QUE JÁ FOi JULGADO ---
        auditorias_antigas = []
        if os.path.exists(self.ARQUIVO_AUDITORIA_GLOBAL):
            try:
                with open(self.ARQUIVO_AUDITORIA_GLOBAL, "r", encoding="utf-8") as f:
                    auditorias_antigas = json.load(f)
                    if not isinstance(auditorias_antigas, list): auditorias_antigas = []
            except Exception:
                pass

        # Cria um set com "IP+Decisao" para saber o que já foi auditado
        ja_auditados = {f"{av.get('ip')}_{av.get('decisao')}" for av in auditorias_antigas}
        
        decisoes_para_auditar = []
        for inc in todas_decisoes:
            assinatura = f"{inc.get('id_alvo')}_{inc.get('veredito')}"
            if assinatura not in ja_auditados:
                decisoes_para_auditar.append(inc)

        if not decisoes_para_auditar:
            logger.info("✅ Nenhuma decisão nova para auditar. Tudo está atualizado.")
            return

        logger.info(f"🔍 Auditando {len(decisoes_para_auditar)} decisões NOVAS e inéditas...")

        timestamp_agora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Preparar a lista que vai crescendo em tempo real
        lista_consolidada = auditorias_antigas.copy()

        for inc in decisoes_para_auditar:
            logger.info(f"A julgar IP: {inc.get('id_alvo', 'Desconhecido')}...")
            
            prompt_usuario = (
                f"Audite a seguinte decisão do SLM Analista SOC:\n\n"
                f"IP ALVO: '{inc.get('id_alvo', '')}'\n"
                f"DADOS DO LOG BRUTO: '{inc.get('padrao_ataque', '')}'\n"
                f"DICA RAG: '{inc.get('dica_rag', '')}'\n"
                f"ANÁLISE DE CONTEXTO DO ANALISTA: '{inc.get('analise_contexto', 'Não informada')}'\n"
                f"DECISÃO FINAL DO ANALISTA: '{inc.get('veredito', '')}'\n\n"
                f"Preencha o JSON com a sua avaliação."
            )
            
            resposta_juiz = self._consultar_juiz(prompt_usuario)
            
            if resposta_juiz:
                try:
                    avaliacao = AvaliacaoIncidente.model_validate_json(resposta_juiz)
                    avaliacao.timestamp_auditoria = timestamp_agora
                    
                    # === SALVAMENTO INCREMENTAL AQUI ===
                    nova_avaliacao_dict = avaliacao.model_dump(by_alias=True)
                    lista_consolidada.append(nova_avaliacao_dict)
                    
                    # Sobrescreve o arquivo imediatamente com a lista atualizada
                    with open(self.ARQUIVO_AUDITORIA_GLOBAL, "w", encoding="utf-8") as f:
                        json.dump(lista_consolidada, f, indent=4, ensure_ascii=False)
                        
                    logger.info(f"✅ IP {inc.get('id_alvo', '')} avaliado e salvo no arquivo!")
                    
                except ValidationError as e:
                    logger.error(f"Juiz gerou JSON inválido: {e}")
            
            # Pausa estendida para a API da Groq
            time.sleep(4)

        logger.info(f"Fim da auditoria! Total de avaliações no arquivo: {len(lista_consolidada)}.")

if __name__ == "__main__":
    juiz = JuizAuditorSOC()
    juiz.executar_auditoria_acumulada()