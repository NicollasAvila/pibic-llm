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

# 1. TROCAMOS GROQ PELA OPENAI
from openai import OpenAI 

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
    parecer_juiz: str = Field(..., description="Crítica técnica e ácida sobre a análise do analista menor.")
    nota_fidelidade_factual: int = Field(..., ge=0, le=10, alias="fidelidade_factual")
    nota_acuracia_decisao: int = Field(..., ge=0, le=10, alias="acuracia_decisao")
    nota_qualidade_raciocinio: int = Field(..., ge=0, le=10, alias="qualidade_raciocinio")
    nota_adesao_instrucao: int = Field(..., ge=0, le=10, alias="adesao_instrucao")
    timestamp_auditoria: Optional[str] = None

class JuizAuditorSOC:
    def __init__(self):
        self.ARQUIVO_PLAYBOOK_GLOBAL = ARQUIVO_PLAYBOOK
        self.ARQUIVO_AUDITORIA_GLOBAL = RESULTADOS_DIR / "auditoria_global.json" 
        
        logger.info("Inicializando Juiz Auditor (Via OpenRouter)...")
        
        # 2. PUXAMOS A CHAVE NOVA
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("Erro: OPENROUTER_API_KEY não encontrada no arquivo .env.")
        
        # 3. O SEGREDO ESTÁ AQUI: Usar a classe OpenAI, mas apontar para a URL do OpenRouter
        self.cliente = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
        )
        
        # 4. ESCOLHA O MODELO NO PADRÃO DO OPENROUTER (Ex: Llama 3.3 70B)
        self.modelo = "nvidia/nemotron-3-super-120b-a12b:free" 

    def _consultar_juiz(self, prompt_usuario):
        prompt_sistema = """Você é um Auditor Sênior de Segurança da Informação nível Tier 3 (Threat Hunter).
Sua função é auditar as decisões de um Analista SOC Nível 1 (IA Menor).
Você é EXTREMAMENTE CRÍTICO, CÉTICO E RIGOROSO. O padrão ouro (Nota 10) é quase inatingível e reservado apenas para análises completas, profundas e técnicas.

[MÉTODO DE PONTUAÇÃO - REGIME DE DEDUÇÃO]
Comece com a nota 10 em cada critério e DEDUZA pontos impiedosamente conforme a régua abaixo:

1. qualidade_raciocinio:
   - Nota 10: Análise profunda. Relaciona IPs, portas, tempo, espaço e cruza com a regra RAG de forma técnica.
   - Nota 6: Análise rasa, genérica ou preguiçosa ("O tráfego é normal e a porta é de navegação"). -> DEDUZA 4 PONTOS IMEDIATAMENTE.
   - Nota 3: Usa apenas respostas curtas, repetitivas ou não explica o contexto do DLP/Upload.

2. fidelidade_factual:
   - Nota 10: Usa os dados exatos do log bruto sem inventar nada.
   - Nota 5: Omite dados cruciais do log na justificativa (Ex: Ignora um pico de Upload de 100MB). -> DEDUZA 5 PONTOS.
   - Nota 0: Inventa dados, portas ou alucina regras não enviadas.

3. acuracia_decisao:
   - Nota 10: Veredito exato e perfeitamente alinhado à instrução do RAG.
   - Nota 0: Errou a decisão final (Ex: RAG pediu Bloquear e a IA deu Falso Positivo).

4. adesao_instrucao:
   - Nota 10: Respeitou todas as regras de formatação e restrições absolutas do sistema.
   - Nota 5: Deixou campos em branco desnecessariamente ou gerou justificativas mal formatadas.
   - Nota 0: Quebrou a estrutura esperada.

Você DEVE retornar EXATAMENTE o seguinte formato JSON e nada mais:
{
    "ip": "<escreva o IP aqui>",
    "decisao": "<escreva a decisão tomada aqui>",
    "parecer_juiz": "<PASSO 1: Pense em voz alta. Escreva uma crítica ácida apontando o que faltou de aprofundamento técnico na análise menor.>",
    "fidelidade_factual": 10,
    "acuracia_decisao": 10,
    "qualidade_raciocinio": 6,
    "adesao_instrucao": 10
}
"""
        try:
            # 5. A SINTAXE DE CHAMADA FICA IDÊNTICA!
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
            logger.error(f"Erro ao consultar OpenRouter (Juiz): {e}")
            return None

    def executar_auditoria_acumulada(self):
        logger.info(f"=== [JUIZ] INICIANDO AUDITORIA NO LIVRO-RAZÃO GLOBAL ===")
        
        if not os.path.exists(self.ARQUIVO_PLAYBOOK_GLOBAL):
            logger.error("Playbook Global não encontrado. Execute o orquestrador primeiro.")
            return

        todas_decisoes = []
        with open(self.ARQUIVO_PLAYBOOK_GLOBAL, "r", encoding="utf-8") as f:
            for linha in f:
                linha = linha.strip()
                if not linha:  
                    continue
                try:
                    incidente = json.loads(linha)
                    todas_decisoes.append(incidente)
                except json.JSONDecodeError as e:
                    logger.warning(f"Ignorando linha malformada no JSONL: {e}")
            
        logger.info(f"Total de {len(todas_decisoes)} decisões acumuladas no Playbook.")

        auditorias_antigas = []
        if os.path.exists(self.ARQUIVO_AUDITORIA_GLOBAL):
            try:
                with open(self.ARQUIVO_AUDITORIA_GLOBAL, "r", encoding="utf-8") as f:
                    auditorias_antigas = json.load(f)
                    if not isinstance(auditorias_antigas, list): auditorias_antigas = []
            except Exception:
                pass

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
                    
                    nova_avaliacao_dict = avaliacao.model_dump(by_alias=True)
                    lista_consolidada.append(nova_avaliacao_dict)
                    
                    with open(self.ARQUIVO_AUDITORIA_GLOBAL, "w", encoding="utf-8") as f:
                        json.dump(lista_consolidada, f, indent=4, ensure_ascii=False)
                        
                    logger.info(f"✅ IP {inc.get('id_alvo', '')} avaliado e salvo no arquivo!")
                    
                except ValidationError as e:
                    logger.error(f"Juiz gerou JSON inválido: {e}")
            
            # No OpenRouter, dependendo da sua tier/créditos, o limite de requisições é diferente do Groq.
            # Se você colocar créditos ($5), pode reduzir esse time.sleep(4) para (1) ou até tirar!
            time.sleep(2) 

        logger.info(f"Fim da auditoria! Total de avaliações no arquivo: {len(lista_consolidada)}.")

if __name__ == "__main__":
    juiz = JuizAuditorSOC()
    juiz.executar_auditoria_acumulada()