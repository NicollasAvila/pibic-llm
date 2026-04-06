import os
import json
import time
import logging
from openai import OpenAI
from dotenv import load_dotenv

# Configuração de Log para acompanhar o terminal
logging.basicConfig(level=logging.INFO, format='[Fábrica_Ouro_Batches] %(message)s', datefmt='%H:%M:%S')
load_dotenv()

class GeradorDatasetOuro:
    def __init__(self):
        # Aponte para o Playbook gerado pela Camada 3 (Incidentes extraídos), não o Log Bruto cru.
        # Se você rodou o soc.bat recentemente sob o modelo 'llama3.2', a pasta deve ser esta:
        self.ARQUIVO_LOGS_BRUTOS = r'C:\Projetos\pibic-llm\resultados\llama3.2\playbook_global.jsonl'
        self.ARQUIVO_SAIDA_UNSLOTH = "resultados/dataset_ouro_unsloth.jsonl"
        self.TAMANHO_LOTE = 3 # Exatamente igual a inferência (O Pulo do Gato)
        
        api_key = os.getenv("OPENROUTER_API_KEY")
        if not api_key:
            raise ValueError("Erro: OPENROUTER_API_KEY não encontrada no .env.")
            
        self.cliente = OpenAI(
            base_url="https://openrouter.ai/api/v1",
            api_key=api_key,
            max_retries=0,
        )
        
        self.modelo = "nvidia/nemotron-3-super-120b-a12b:free"
        
        # 🔴 ESTE FOI O ERRO DIAGNOSTICADO: AGORA O SYSTEM PROMPT É 100% IGUAL AO DA PRODUÇÃO
        self.prompt_sistema_slm = """Você é um Analista de SOC Sênior. Sua tarefa é avaliar incidentes de rede usando a Cadeia de Pensamento.

[COMO VOCÊ SERÁ AVALIADO (MÉTRICAS DE AUDITORIA)]
Suas respostas passarão por uma auditoria rigorosa. Para tirar nota máxima, você DEVE focar nestes 4 quesitos:
1. Qualidade de Raciocínio: NUNCA dê respostas genéricas. Você deve cruzar IP, Porta, Tempo, Espaço e as regras de Firewall.
2. Fidelidade Factual: Você é OBRIGADO a citar os números exatos do log (Ex: Megabytes de upload transferidos, quantidade de eventos, portas alvo).
3. Acurácia da Decisão: A lógica da sua justificativa não pode contradizer a decisão tomada.
4. Adesão à Instrução: O Veredito final deve ser a palavra exata solicitada (FALSO_POSITIVO, BLOQUEAR ou MONITORAR) e a formatação JSONL deve ser impecável.

[REGRAS DE DECISÃO E USO DO RAG]
1. O RAG atua como seu conselheiro principal (Playbook Histórico), mas ELE NÃO É INFALÍVEL.
2. Você DEVE validar se os dados brutos do log realmente confirmam a hipótese do RAG.
3. Se os dados baterem perfeitamente com a dica do RAG, siga o veredito dele com 'nivel_confianca' ALTA.
4. CLÁUSULA DE EXCEÇÃO: Se houver uma contradição gritante (Ex: O RAG diz que é um crawler benigno, mas o log mostra 500MB de upload para um IP suspeito e movimentação lateral), você DEVE ignorar o RAG, mudar o veredito para INVESTIGAR ou BLOQUEAR, e colocar a confiança como MÉDIA ou BAIXA.

[CADEIA DE PENSAMENTO OBRIGATÓRIA]
Para cada incidente, você deve gerar os dados nesta EXATA ordem:
1. 'analise_contexto': Descreva os dados técnicos. (Ex: "O log indica 344 eventos focados na porta 80 com origem na zona DMZ3. O DLP detectou um upload anômalo de 119.1 MB. Apesar da anomalia de volume, a regra do SIPROS e a dica do RAG confirmam tratar-se de um web-crawler benigno mapeado.")
2. 'justificativa': Resuma a sua análise e os dados cruzados.
3. 'veredito': Dê a sentença exata.
4. 'nivel_confianca': Dê a confiança (Sempre ALTA se seguir o RAG)."""

    def _pedir_gabarito(self, prompt_incidentes_json):
        # 🔴 PROFESSOR AGORA PEDE O JSON EM ESTRUTURA GLOBAL: "avaliacoes": []
        prompt_professor = f"""Você é um Mestre em Cibersegurança elaborando o Gabarito Ouro para treinar uma IA menor no SOC.
Sua missão é ler um Array (Lote) contendo {self.TAMANHO_LOTE} incidentes abaixo e gerar as respostas PERFEITAS em Batch.

REGRAS ESTONTEANTES DE RIGOR:
1. FIDELIDADE FACTUAL: Use APENAS os dados informados. 
2. ACURÁCIA DA DECISÃO: Valide o RAG. Discorde e mude o veredito se houver contradição absurda (ex: anomalia enorme que o RAG diz ser normal).

RETORNE EXATAMENTE NESTE FORMATO JSON ROOT e nada mais:
{{
  "avaliacoes": [
      {{ "analise_contexto": "...", "justificativa": "...", "veredito": "...", "nivel_confianca": "..." }},
      ... (repetir para todos os itens do lote da entrada)
  ]
}}

INCIDENTES EM BATCH:
{prompt_incidentes_json}
"""
        max_tentativas = 5
        for tentativa in range(max_tentativas):
            try:
                resposta = self.cliente.chat.completions.create(
                    messages=[
                        {"role": "system", "content": "Você é um gerador de datasets implacável que só retorna JSON puro."},
                        {"role": "user", "content": prompt_professor}
                    ],
                    model=self.modelo,
                    temperature=0.0,
                    response_format={"type": "json_object"}
                )
                
                if not hasattr(resposta, 'choices') or not resposta.choices:
                    logging.warning(f"⚠️ Resposta da API Ouro veio sem 'choices' (Possível erro no upstream). Conteúdo puro: {resposta}")
                    time.sleep(10)
                    continue
                    
                return resposta.choices[0].message.content
            except Exception as e:
                erro_str = str(e).lower()
                if "429" in erro_str or "rate limit" in erro_str:
                    tempo = 20 * (tentativa + 1)
                    logging.warning(f"⏳ Rate Limit. Dormindo {tempo}s... ({tentativa+1}/{max_tentativas})")
                    time.sleep(tempo)
                elif "nonetype" in erro_str or "subscriptable" in erro_str:
                    logging.warning(f"⚠️ Falha de estrutura na resposta (NoneType). Tentando de novo em 10s... ({tentativa+1}/{max_tentativas})")
                    time.sleep(10)
                else:
                    logging.error(f"❌ Erro na API Ouro ({e}). Tentando novamente em 5s... ({tentativa+1}/{max_tentativas})")
                    time.sleep(5)
        return None

    def gerar_dataset(self):
        logging.info("🔥 Iniciando a Forja de Conhecimento Roteado em Batches 🔥")
        
        TOTAL_ITENS_ALVO = 150
        LOTE_MAXIMO = TOTAL_ITENS_ALVO // self.TAMANHO_LOTE
        
        # Leitura da quantidade salva baseada em linhas jsonl (1 linha = 1 lote de 3 agora)
        lotes_salvos = 0
        if os.path.exists(self.ARQUIVO_SAIDA_UNSLOTH):
            with open(self.ARQUIVO_SAIDA_UNSLOTH, 'r', encoding='utf-8') as f_check:
                lotes_salvos = sum(1 for linha in f_check if linha.strip())
                
        restantes = LOTE_MAXIMO - lotes_salvos
        
        if restantes <= 0:
            logging.info(f"✅ Dataset completo com {lotes_salvos} lotes gigantes!")
            return
            
        logging.info(f"🔄 Retomando: {lotes_salvos} lotes salvos. Faltam {restantes}.")
        
        logs_totais = []
        if not os.path.exists(self.ARQUIVO_LOGS_BRUTOS):
            logging.error(f"Arquivo RAW não encontrado: {self.ARQUIVO_LOGS_BRUTOS}")
            return
            
        with open(self.ARQUIVO_LOGS_BRUTOS, 'r', encoding='utf-8') as f:
            for linha in f:
                if linha.strip():
                    logs_totais.append(json.loads(linha.strip()))
                    
        import random
        random.shuffle(logs_totais)
        
        incidentes_processados = 0
        
        os.makedirs("resultados", exist_ok=True)
        with open(self.ARQUIVO_SAIDA_UNSLOTH, 'a', encoding='utf-8') as f_out:
            for i in range(0, restantes * self.TAMANHO_LOTE, self.TAMANHO_LOTE):
                batch_incidentes = logs_totais[i:i + self.TAMANHO_LOTE]
                
                # Prepara o JSON exato da camada de agente
                lista_dicts = []
                for log in batch_incidentes:
                    lista_dicts.append({
                        "id_alvo": log.get("id_alvo", "N/A"),
                        "padrao_ataque": log.get("padrao_ataque", "N/A"),
                        "dica_rag": log.get("dica_rag", "N/A")
                    })
                
                prompt_usuario = json.dumps(lista_dicts, ensure_ascii=False, indent=2)
                lote_atual = lotes_salvos + (i // self.TAMANHO_LOTE) + 1
                logging.info(f"[{lote_atual}/{LOTE_MAXIMO}] Pedindo sabedoria para Batch de IPs: {[d['id_alvo'] for d in lista_dicts]}")
                
                resposta_json_str = self._pedir_gabarito(prompt_usuario)
                
                if resposta_json_str:
                    try:
                        # Extrai para ver se o LLM seguiu a regra "avaliacoes"
                        resposta_limpa = json.loads(resposta_json_str)
                        if "avaliacoes" not in resposta_limpa:
                            resposta_limpa = {"avaliacoes": resposta_limpa} # Fallback de proteção
                        
                        # ALINHAMENTO ABSOLUTO DE FINE TUNING: 
                        # role: user deve ser o JSON (lista)...
                        # role: assistant deve ser o JSON (dict com "avaliacoes")...
                        linha_treinamento = {
                            "messages": [
                                {"role": "system", "content": self.prompt_sistema_slm},
                                {"role": "user", "content": prompt_usuario},
                                {"role": "assistant", "content": json.dumps(resposta_limpa, ensure_ascii=False)}
                            ]
                        }
                        
                        f_out.write(json.dumps(linha_treinamento, ensure_ascii=False) + "\n")
                        f_out.flush() 
                        logging.info("✅ Batch de Gabarito 10/10 Salvo!")
                        
                    except json.JSONDecodeError:
                        logging.error("❌ Nemotron quebrou o JSON, pulando lote...")
                
                time.sleep(10) # Respeita Rate Limits do free tier
                
        logging.info(f"🎉 Forja Finalizada em Batches! {self.ARQUIVO_SAIDA_UNSLOTH}")

if __name__ == "__main__":
    gerador = GeradorDatasetOuro()
    gerador.gerar_dataset()