import ollama
import json
import pandas as pd
import os
import time
from groq import Groq
from dotenv import load_dotenv

# 1. Carrega as variáveis de ambiente (Chave da Groq)
load_dotenv() 

# --- CONFIGURAÇÕES DO AMBIENTE ---
# Caminhos relativos a partir da pasta 'src'
ARQUIVO_ENTRADA = "../dados/dataset_sintetico.json"
ARQUIVO_SAIDA_CSV = "../resultados/relatorio_juiz.csv"

# Definição dos Modelos
MODELO_ALUNO = "llama3-cyber"           # Seu modelo local (Ollama)
MODELO_JUIZ = "llama-3.3-70b-versatile" # Modelo Inteligente da Groq (Nuvem)

# --- PROMPTS ---

# PROMPT DO ALUNO (Atualizado para ser DETALHISTA e evitar notas baixas)
SYSTEM_PROMPT_ALUNO = """
Você é um Analista de SOC Sênior. Analise o log de segurança fornecido no formato JSON (Wazuh).

SUA MISSÃO: Gerar um relatório técnico rico e detalhado.
REGRAS OBRIGATÓRIAS:
1. No campo 'resumo_incidente', NÃO seja breve. Descreva o cenário completo: quem atacou (IP/País), quem foi o alvo, qual ferramenta foi usada e se houve bloqueio (WAF/Firewall/IPS).
2. Identifique a ameaça com o nome técnico exato (ex: Ransomware WannaCry, SQL Injection Blind).
3. Extraia o IoC (Hash, IP ou URL) que estiver nos dados.

Responda APENAS um JSON com esta estrutura:
{
  "resumo_incidente": "Texto detalhado descrevendo todo o contexto do ataque e a ação tomada",
  "nome_ameaca": "Nome técnico da ameaça",
  "ioc_extraido": "O dado técnico malicioso (Hash/IP/URL)",
  "acao_sugerida": "Bloquear, Isolar Host ou Investigar"
}
"""

# PROMPT DO JUIZ (A Rubrica de Correção)
PROMPT_JUIZ = """
Você é um Auditor Técnico de Cibersegurança (QA).
Compare os fatos do Log Original com a Análise feita pela IA (Analista Júnior).

DADOS:
1. LOG ORIGINAL (Fato): {log_orig}
2. GABARITO (O que realmente aconteceu): {cenario_real}
3. RESPOSTA DA IA: {resp_ia}

CRITÉRIOS DE AVALIAÇÃO (0 a 10):
- Precisão (Peso 5): A IA acertou o tipo de ataque? (Ex: Não confundiu Ransomware com Phishing?)
- Detalhes (Peso 3): O resumo cita o contexto (ex: bloqueio, WAF, origem)?
- IoC (Peso 2): O Hash/IP extraído está correto?

SAÍDA OBRIGATÓRIA (JSON puro):
{{
  "nota": <numero_float>,
  "motivo": "<explique o erro ou o acerto em 1 frase>",
  "acertou_ataque": <true/false>
}}
"""

def main():
    # Validação de Segurança
    chave_groq = os.getenv("GROQ_API_KEY")
    if not chave_groq:
        print("❌ ERRO CRÍTICO: Chave GROQ_API_KEY não encontrada no arquivo .env!")
        return

    cliente_groq = Groq(api_key=chave_groq)

    # Carregamento dos Dados
    if not os.path.exists(ARQUIVO_ENTRADA):
        print(f"❌ Arquivo {ARQUIVO_ENTRADA} não encontrado. Rode o gerar_dataset.py primeiro!")
        return
        
    with open(ARQUIVO_ENTRADA, "r", encoding="utf-8") as f:
        dataset = json.load(f)

    print(f"⚖️  Iniciando Julgamento de {len(dataset)} casos com o Juiz {MODELO_JUIZ}...\n")
    resultados = []

    # --- LOOP DE AVALIAÇÃO ---
    for i, caso in enumerate(dataset):
        cenario_real = caso.get("_gabarito_ataque", "Desconhecido")
        # Mostra apenas o começo do cenário no terminal para não poluir
        print(f"▶️  Caso {i+1}: {cenario_real[:50]}...")

        # ---------------------------------------------------------
        # PASSO A: O ALUNO RESPONDE (Local - Ollama)
        # ---------------------------------------------------------
        start = time.time()
        try:
            resp_aluno = ollama.chat(
                model=MODELO_ALUNO, 
                messages=[
                    {'role': 'system', 'content': SYSTEM_PROMPT_ALUNO},
                    {'role': 'user', 'content': json.dumps(caso)}
                ],
                # FIX: Aumentamos para 512 tokens para evitar JSON cortado
                options={'num_predict': 512, 'temperature': 0.1} 
            )['message']['content']
        except Exception as e:
            print(f"   ❌ Erro no Ollama (Aluno): {e}")
            resp_aluno = "{}" 
        
        tempo_inferencia = time.time() - start

        # ---------------------------------------------------------
        # PASSO B: O JUIZ AVALIA (Nuvem - Groq)
        # ---------------------------------------------------------
        try:
            prompt_preenchido = PROMPT_JUIZ.format(
                log_orig=json.dumps(caso), 
                resp_ia=resp_aluno,
                cenario_real=cenario_real
            )

            resp_juiz = cliente_groq.chat.completions.create(
                messages=[{"role": "user", "content": prompt_preenchido}],
                model=MODELO_JUIZ,
                temperature=0, # Temperatura 0 para ser objetivo
                response_format={"type": "json_object"} # Força resposta JSON válida
            )
            
            avaliacao = json.loads(resp_juiz.choices[0].message.content)
            
            # Feedback visual imediato
            cor = "⭐" if avaliacao['nota'] >= 9 else "⚠️ "
            print(f"   {cor} Nota: {avaliacao['nota']} | {avaliacao['motivo']}")

            # Guardar resultados
            resultados.append({
                "ID": i+1,
                "Cenario_Real": cenario_real,
                "Nota_Juiz": avaliacao['nota'],
                "Motivo": avaliacao['motivo'],
                "Acertou": avaliacao['acertou_ataque'],
                "Tempo_Resp(s)": round(tempo_inferencia, 2),
                "Resposta_IA": resp_aluno # Guardamos a resposta completa
            })

        except Exception as e:
            print(f"   ❌ Erro no Juiz (Groq): {e}")

    # --- RELATÓRIO FINAL ---
    # Cria a pasta se não existir
    os.makedirs(os.path.dirname(ARQUIVO_SAIDA_CSV), exist_ok=True)
    
    df = pd.DataFrame(resultados)
    df.to_csv(ARQUIVO_SAIDA_CSV, index=False)
    
    media = df['Nota_Juiz'].mean() if not df.empty else 0

    print("\n" + "="*60)
    print(f"✅ JULGAMENTO CONCLUÍDO!")
    print(f"📄 Relatório salvo em: {ARQUIVO_SAIDA_CSV}")
    print(f"📊 Média Geral das Notas: {media:.2f} / 10.0")
    print("="*60)

if __name__ == "__main__":
    main()