import os
import json
import time
import logging
from openai import OpenAI
from dotenv import load_dotenv

# Configuração de Log para acompanhar o terminal
logging.basicConfig(level=logging.INFO, format='[Fábrica_Ouro] %(message)s', datefmt='%H:%M:%S')
load_dotenv()

class GeradorDatasetOuro:
    def __init__(self):
        # Aponte para o arquivo que contém os logs originais capturados pelo SOC
        self.ARQUIVO_LOGS_BRUTOS = 'C:\Projetos\pibic-llm\dados\raw\ossec-archive-13.log'
        
        # Onde o dataset final pronto para o Unsloth será salvo
        self.ARQUIVO_SAIDA_UNSLOTH = "resultados/dataset_ouro_unsloth.jsonl"
        
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("Erro: OPENROUTER_API_KEY não encontrada no .env.")
            
        self.cliente = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            max_retries=0, # Proteção contra Rate Limit
        )
        
        # O Professor que fará as provas perfeitas
        self.modelo = "nvidia/nemotron-3-super-120b-a12b:free"
        
        # 🔴 PROMPT DA SLM ATUALIZADO COM OS 4 QUESITOS EXATOS
        # Este é o DNA que o Llama 3.2 vai absorver durante o treinamento
        self.prompt_sistema_slm = """Você é um Analista de SOC Sênior. Sua tarefa é avaliar incidentes de rede usando a Cadeia de Pensamento.

[OS 4 QUESITOS DE AVALIAÇÃO OBRIGATÓRIOS]
1. Fidelidade Factual: Baseie-se EXCLUSIVAMENTE nos dados. NUNCA invente fatos, zonas de rede (ex: DMZ inexistente) ou IPs.
2. Qualidade de Raciocínio: Cruze explicitamente IP, Porta, MBs transferidos e Zona real na sua Cadeia de Pensamento.
3. Acurácia da Decisão: O RAG é seu conselheiro. Se os dados baterem com o comportamento esperado, siga-o (FALSO_POSITIVO). Se contradizerem (ex: upload gigante, exfiltração clara), você DEVE discordar e mudar o veredito (BLOQUEAR ou INVESTIGAR).
4. Adesão à Instrução: Responda APENAS usando a estrutura JSON estrita exigida.

[FORMATO JSON OBRIGATÓRIO]
{
    "analise_contexto": "Sua cadeia de pensamento detalhada cruzando os dados e justificando a anomalia ou normalidade.",
    "justificativa": "Resumo rápido da validação cruzada com a regra RAG.",
    "veredito": "FALSO_POSITIVO, BLOQUEAR ou MONITORAR",
    "nivel_confianca": "ALTA, MEDIA ou BAIXA"
}"""

    def _pedir_gabarito(self, prompt_incidente):
        # 🔴 PROMPT DO PROFESSOR (NEMOTRON)
        # Ele é instruído a forjar respostas que tirem nota 10/10 nos 4 quesitos
        prompt_professor = f"""Você é um Mestre em Cibersegurança forjando o Gabarito de Ouro para treinar uma IA menor no nosso SOC.
Sua missão é ler o log abaixo e gerar a resposta JSON PERFEITA, gabaritando os 4 quesitos de auditoria.

REGRAS PARA GABARITAR (NOTA 10/10):
1. FIDELIDADE FACTUAL: Use APENAS os dados do log. Se a zona é CHEGADA_INT, use CHEGADA_INT. Zero invenções.
2. QUALIDADE DE RACIOCÍNIO: Cite os números na `analise_contexto`! Explique tecnicamente a porta e os Megabytes.
3. ACURÁCIA DA DECISÃO: Valide a Dica RAG. Se o upload for gigante para um crawler benigno, discorde do RAG, explique a contradição e bloqueie.
4. ADESÃO: Retorne estritamente o JSON esperado.

INCIDENTE BRUTO:
{prompt_incidente}
"""
        max_tentativas = 5
        for tentativa in range(max_tentativas):
            try:
                resposta = self.cliente.chat.completions.create(
                    messages=[
                        {"role": "system", "content": "Você é um gerador de datasets corporativos implacável, rigoroso e imune a alucinações."},
                        {"role": "user", "content": prompt_professor}
                    ],
                    model=self.modelo,
                    temperature=0.0, # Temperatura 0 para ser determinístico matemático
                    response_format={"type": "json_object"}
                )
                return resposta.choices[0].message.content
            except Exception as e:
                erro_str = str(e).lower()
                if "429" in erro_str or "rate limit" in erro_str:
                    tempo = 20 * (tentativa + 1)
                    logging.warning(f"⏳ OpenRouter Rate Limit. Dormindo {tempo}s... ({tentativa+1}/{max_tentativas})")
                    time.sleep(tempo)
                else:
                    logging.error(f"❌ Erro fatal na API: {e}")
                    return None
        return None

    def gerar_dataset(self):
        import random 
        
        logging.info("🔥 Iniciando a Forja de Conhecimento (Nemotron 120B) 🔥")
        
        MAX_GABARITOS = 150
        
        # 🔴 1. SISTEMA ANTI-CRASH (CHECKPOINT)
        gabaritos_prontos = 0
        if os.path.exists(self.ARQUIVO_SAIDA_UNSLOTH):
            with open(self.ARQUIVO_SAIDA_UNSLOTH, 'r', encoding='utf-8') as f_check:
                gabaritos_prontos = sum(1 for linha in f_check if linha.strip())
                
        restantes = MAX_GABARITOS - gabaritos_prontos
        
        if restantes <= 0:
            logging.info(f"✅ O dataset já possui {gabaritos_prontos} gabaritos de Ouro. O arquivo está completo!")
            return
            
        logging.info(f"🔄 Retomando progresso: {gabaritos_prontos} salvos no SSD. Faltam gerar {restantes} gabaritos.")
        
        # 2. Carrega os logs brutos
        logs_totais = []
        if not os.path.exists(self.ARQUIVO_LOGS_BRUTOS):
            logging.error(f"Arquivo não encontrado: {self.ARQUIVO_LOGS_BRUTOS}")
            return
            
        with open(self.ARQUIVO_LOGS_BRUTOS, 'r', encoding='utf-8') as f:
            for linha in f:
                if linha.strip():
                    logs_totais.append(json.loads(linha.strip()))
                    
        random.shuffle(logs_totais)
        
        # Seleciona apenas a quantidade exata que falta para chegar em 150
        logs_amostra = logs_totais[:restantes]

        # 🔴 3. MODO 'a' (APPEND) - Adiciona sem apagar o que já foi feito
        with open(self.ARQUIVO_SAIDA_UNSLOTH, 'a', encoding='utf-8') as f_out:
            for idx, log in enumerate(logs_amostra):
                numero_atual = gabaritos_prontos + idx + 1
                logging.info(f"[{numero_atual}/{MAX_GABARITOS}] Destilando sabedoria para o IP: {log.get('id_alvo', 'Desconhecido')}")
                
                prompt_incidente = (
                    f"IP ALVO: '{log.get('id_alvo', '')}'\n"
                    f"DADOS DO LOG BRUTO: '{log.get('padrao_ataque', '')}'\n"
                    f"DICA RAG: '{log.get('dica_rag', '')}'"
                )
                
                resposta_json_str = self._pedir_gabarito(prompt_incidente)
                
                if resposta_json_str:
                    try:
                        resposta_limpa = json.loads(resposta_json_str)
                        
                        linha_treinamento = {
                            "messages": [
                                {"role": "system", "content": self.prompt_sistema_slm},
                                {"role": "user", "content": prompt_incidente},
                                {"role": "assistant", "content": json.dumps(resposta_limpa, ensure_ascii=False)}
                            ]
                        }
                        
                        f_out.write(json.dumps(linha_treinamento, ensure_ascii=False) + "\n")
                        # 🔴 O FLUSH GARANTE O SALVAMENTO IMEDIATO NO HD A CADA LINHA:
                        f_out.flush() 
                        logging.info("✅ Gabarito 10/10 Salvo no disco!")
                        
                    except json.JSONDecodeError:
                        logging.error("❌ Nemotron quebrou o JSON, pulando...")
                
                time.sleep(12)
                
        logging.info(f"🎉 Forja Finalizada! Arquivo blindado e pronto no caminho: {self.ARQUIVO_SAIDA_UNSLOTH}")

if __name__ == "__main__":
    gerador = GeradorDatasetOuro()
    gerador.gerar_dataset()