import json
import os
from pydantic import BaseModel, Field, ValidationError
from groq import Groq

# ==========================================
# Schemas de Avaliação baseados no ST-Bench
# ==========================================
class AvaliacaoSTBench(BaseModel):
    raciocinio_etiologico: int = Field(
        ..., ge=0, le=1, 
        description="1 se inferiu a semântica global (ex: scan coordenado vs falso positivo). 0 se errou."
    )
    identificacao_entidades: int = Field(
        ..., ge=0, le=1, 
        description="1 se reconheceu os papéis dos IPs (Atacante/Alvo/C2) no grafo. 0 caso contrário."
    )
    correlacao_espacial: int = Field(
        ..., ge=0, le=1, 
        description="1 se avaliou a lateralização ou o tempo de propagação (burst). 0 caso contrário."
    )
    uso_genuino_do_grafo: int = Field(
        ..., ge=0, le=1, 
        description="1 se usou a estrutura do grafo para justificar o veredicto. 0 se analisou IPs de forma isolada."
    )
    formato_valido: int = Field(
        ..., ge=0, le=1,
        description="1 se o Agente gerou JSON estrito para o Playbook, sem tagarelar. 0 caso contrário."
    )

class VeredictoJuiz(BaseModel):
    metricas: AvaliacaoSTBench
    nota_final: float = Field(..., description="Soma das métricas (0 a 5).")
    justificativa: str = Field(..., description="Análise crítica das falhas ou acertos do Agente.")

# ==========================================
# Classe LLM-as-a-Judge
# ==========================================
class JuizSTReasoner:
    def __init__(self, model_name: str = "llama-3.1-70b-versatile"):
        self.client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model_name = model_name
        
        self.system_prompt = """
        Você é um avaliador rigoroso (LLM-as-a-Judge) de um Agente de SOC Nível 1.
        Sua tarefa é ler a decisão do Agente e avaliá-la com base no contexto espaço-temporal fornecido.
        
        REGRAS CRÍTICAS:
        - Penalize com 0 em 'uso_genuino_do_grafo' se o agente apenas tomou a decisão por uma palavra-chave (ex: 'Failed Password') sem conectar a frequência temporal ou alvos múltiplos.
        - O agente não deve alucinar ameaças fora do contexto do RAG.
        
        Retorne APENAS um JSON válido seguindo o schema solicitado.
        """

    def avaliar(self, contexto_completo: str, resposta_agente: str, gabarito_real: str) -> VeredictoJuiz | None:
        prompt_usuario = f"""
        [CONTEXTO DE ENTRADA (Camada 1 e 2)]
        {contexto_completo}
        
        [RESPOSTA GERADA PELO AGENTE (Camada 3)]
        {resposta_agente}

        [GABARITO ESPERADO DO RED TEAM]
        {gabarito_real}
        """

        try:
            response = self.client.chat.completions.create(
                messages=[
                    {"role": "system", "content": self.system_prompt},
                    {"role": "user", "content": prompt_usuario}
                ],
                model=self.model_name,
                temperature=0.0,
                response_format={"type": "json_object"}
            )
            
            return VeredictoJuiz(**json.loads(response.choices[0].message.content))
        except ValidationError as e:
            print(f"[Erro de Schema] O Juiz falhou na validação: {e}")
            return None
        except Exception as e:
            print(f"[Erro de API] Falha na Groq: {e}")
            return None