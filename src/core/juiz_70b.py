import os
import json
from dotenv import load_dotenv
from groq import Groq
from pydantic import BaseModel, Field

# Carrega as chaves do ficheiro .env
load_dotenv()

# --- 1. DEFINIÇÃO DA RUBRICA DE AVALIAÇÃO (O GABARITO DO JUIZ) ---
class AvaliacaoJuiz(BaseModel):
    fidelidade_factual: int = Field(description="Nota 0-10: O SLM inventou dados? (10 = Não inventou nada, baseou-se apenas no contexto)")
    acuracia_decisao: int = Field(description="Nota 0-10: A decisão (BLOQUEAR/MONITORAR/FALSO_POSITIVO) foi a mais correta para a segurança?")
    qualidade_raciocinio: int = Field(description="Nota 0-10: A justificativa usou os conceitos de Tempo (frequência) e Espaço (alvos/nós)?")
    adesao_instrucao: int = Field(description="Nota 0-10: O SLM foi direto ou gerou texto inútil/conversa?")
    comentario_auditoria: str = Field(description="Um parágrafo curto (max 3 linhas) do Juiz justificando as notas dadas.")

# --- 2. CONFIGURAÇÃO DO JUIZ (MODELO PESADO) ---
# Atualizado para o motor mais recente da Groq
MODELO_JUIZ = "llama-3.3-70b-versatile" 
cliente_groq = Groq(api_key=os.environ.get("GROQ_API_KEY"))

def auditar_decisoes_slm():
    caminho_playbook = "resultados/playbook_lote_1.json"
    caminho_auditoria = "resultados/auditoria_lote_1.json"
    
    if not os.path.exists(caminho_playbook):
        print("❌ Erro: Playbook não encontrado. Rode o main_pipeline.py primeiro.")
        return

    with open(caminho_playbook, "r", encoding="utf-8") as f:
        playbook = json.load(f)
        
    incidentes = playbook.get("incidentes", [])
    if not incidentes:
        print("Nenhum incidente para avaliar.")
        return

    # Para não gastar muitos tokens na demonstração, o Juiz avalia apenas os 3 primeiros incidentes
    amostra_para_auditoria = incidentes[:3]
    resultados_auditoria = []

    print(f"⚖️ Iniciando Tribunal de Auditoria (Modelo: {MODELO_JUIZ})")
    print(f"Analisando {len(amostra_para_auditoria)} caso(s) usando Context-Grounded Evaluation...\n")

    for incidente in amostra_para_auditoria:
        alvo = incidente.get("id_alvo")
        veredito_slm = incidente.get("veredito")
        justificativa_slm = incidente.get("justificativa")
        
        # --- O SEGREDO ESTÁ AQUI: ENVIAR O CONTEXTO ORIGINAL ---
        contexto_original = f"""
        [CENA DO CRIME - LOGS COMPRIMIDOS]
        - IP Alvo: {alvo}
        - Frequência de Acessos: {incidente.get('frequencia_eventos')} acessos
        - Alvos Distintos na Rede: {incidente.get('alvos_distintos')}
        - Portas Atacadas: {incidente.get('portas_frequentes')}
        """
        
        # Transformamos a nossa classe Pydantic num Schema JSON legível para a IA
        esquema_esperado = json.dumps(AvaliacaoJuiz.model_json_schema(), indent=2)
        
        prompt_juiz = f"""Você é um Auditor Sênior de Cibersegurança.
Sua tarefa é avaliar a decisão tomada por um Analista Júnior (um SLM de 8B parâmetros).

{contexto_original}

[AÇÃO TOMADA PELO ANALISTA JÚNIOR]
- Veredito Escolhido: {veredito_slm}
- Justificativa Escrita: {justificativa_slm}

OBRIGATÓRIO: Você deve retornar APENAS um JSON válido. Não adicione nenhum texto antes ou depois. 
O JSON deve seguir EXATAMENTE esta estrutura de chaves:
{esquema_esperado}
"""
        
        print(f"Auditando decisão sobre o IP: {alvo}...")
        
        try:
            resposta = cliente_groq.chat.completions.create(
                model=MODELO_JUIZ,
                messages=[{"role": "user", "content": prompt_juiz}],
                temperature=0.0, # Temperatura 0 = Avaliação matemática e fria, sem criatividade
                response_format={"type": "json_object"}
            )
            
            # Força a extração e validação do JSON usando o Pydantic que criamos
            json_resposta = json.loads(resposta.choices[0].message.content)
            avaliacao_validada = AvaliacaoJuiz(**json_resposta)
            
            # Guardamos a avaliação juntando quem foi avaliado e as notas
            resultados_auditoria.append({
                "ip_avaliado": alvo,
                "veredito_slm": veredito_slm,
                "notas": avaliacao_validada.model_dump()
            })
            print(f"✅ Auditoria concluída para {alvo}.")
            
        except Exception as e:
            print(f"❌ Erro ao auditar o IP {alvo}: {e}")

    # Salva o relatório final do Juiz
    with open(caminho_auditoria, "w", encoding="utf-8") as f:
        json.dump(resultados_auditoria, f, indent=4, ensure_ascii=False)
        
    print(f"\n👨‍⚖️ Sessão encerrada. Relatório de Auditoria salvo em: {caminho_auditoria}")

if __name__ == "__main__":
    auditar_decisoes_slm()