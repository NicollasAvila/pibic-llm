import os
import json
import logging
import re
from typing import List
from pydantic import BaseModel, Field
from groq import Groq
from dotenv import load_dotenv

# Carrega as variáveis do ficheiro .env (como a GROQ_API_KEY)
load_dotenv()

logger = logging.getLogger("Camada3_Agente")

# --- 1. DEFINIÇÃO DO SCHEMA (PYDANTIC) ---
class Incidente(BaseModel):
    id_alvo: str = Field(description="IP ou identificador do atacante")
    veredito: str = Field(description="Decisão da IA: BLOQUEAR, MONITORAR ou FALSO_POSITIVO")
    justificativa: str = Field(description="Explicação baseada no contexto espaço-temporal e RAG")

class RelatorioBatch(BaseModel):
    incidentes: List[Incidente]


# --- 2. CLASSE DO AGENTE ---
class AgenteSegurancaSLM:
    def __init__(self, simular_sem_gpu=False):
        self.simular = simular_sem_gpu
        self.api_key = os.environ.get("GROQ_API_KEY")
        
        if self.simular:
            logger.info("Camada 3 inicializada em MODO SIMULAÇÃO (Mock).")
        else:
            if not self.api_key:
                logger.error("🚨 GROQ_API_KEY não encontrada! Verifique o seu ficheiro .env.")
                raise ValueError("Chave da Groq ausente.")
                
            self.client = Groq(api_key=self.api_key)
            self.modelo = "llama-3.3-70b-versatile" # O modelo Llama 3 de 70B super rápido da Groq
            logger.info(f"Camada 3 inicializada com IA REAL conectada à Groq (Modelo: {self.modelo}).")

    def gerar_playbook_lote(self, texto_para_ia: str) -> RelatorioBatch:
        """
        Envia o texto ST-Align para o Llama 3 julgar e devolve o Pydantic validado.
        """
        if self.simular:
            # Lógica antiga de simulação para testes
            ips_encontrados = re.findall(r'ORIGEM:\s*(\S+)', texto_para_ia)
            lista_incidentes = []
            for ip in set(ips_encontrados):
                veredito = "MONITORAR" if ip.startswith("10.") or ip.startswith("192.") else "BLOQUEAR"
                inc_mock = Incidente(id_alvo=ip, veredito=veredito, justificativa="Simulação de IA concluída.")
                lista_incidentes.append(inc_mock)
            return RelatorioBatch(incidentes=lista_incidentes)

        # === INTEGRAÇÃO COM A IA REAL (GROQ) ===
        logger.info("A enviar contexto Espaço-Temporal para o Llama 3 70B (Groq)...")
        
        prompt_sistema = """És um Analista de SOC Nível 3 Especialista em Raciocínio Espaço-Temporal.
O teu trabalho é avaliar eventos extraídos de um firewall (ST-ALIGN) e as dicas de inteligência (RAG).
Para cada ORIGEM (IP), deves decidir o veredito:
- BLOQUEAR (se for uma ameaça clara, externa ou ataque de força bruta).
- MONITORAR (se for atividade suspeita dentro da rede interna ou que necessite de observação).
- FALSO_POSITIVO (se for tráfego normal e benigno).

A tua justificativa deve citar explicitamente o comportamento TEMPORAL (frequência) e ESPACIAL (topologia/nós).

DEVES responder APENAS com um objeto JSON válido, seguindo rigorosamente esta estrutura:
{
    "incidentes": [
        {
            "id_alvo": "IP",
            "veredito": "DECISAO",
            "justificativa": "A tua análise detalhada"
        }
    ]
}"""

        try:
            # Faz a chamada à API da Groq forçando a saída em JSON
            resposta = self.client.chat.completions.create(
                model=self.modelo,
                messages=[
                    {"role": "system", "content": prompt_sistema},
                    {"role": "user", "content": f"Analisa os seguintes eventos e gera o JSON de resposta:\n\n{texto_para_ia}"}
                ],
                temperature=0.1, # Temperatura baixa para o modelo ser analítico e não inventar
                response_format={"type": "json_object"}
            )
            
            conteudo_json = resposta.choices[0].message.content
            dados_dict = json.loads(conteudo_json)
            
            # O Pydantic valida o JSON gerado pelo LLM
            relatorio = RelatorioBatch(**dados_dict)
            return relatorio

        except Exception as e:
            logger.error(f"Erro na comunicação com a Groq ou falha na validação JSON: {e}")
            return RelatorioBatch(incidentes=[])


    # --- 3. A AÇÃO AGÊNTICA (MCP ATIVO) ---
    def executar_mcp_salvar_lote(self, relatorio_batch: RelatorioBatch, num_lote: int):
        if not relatorio_batch or not relatorio_batch.incidentes:
            return
            
        logger.info(f"=== [MCP] INICIANDO EXECUÇÃO DAS FERRAMENTAS PARA O LOTE {num_lote} ===")
        
        os.makedirs("resultados", exist_ok=True)
        caminho_arquivo = f"resultados/playbook_lote_{num_lote}.json"
        
        with open(caminho_arquivo, "w", encoding="utf-8") as f:
            json.dump(relatorio_batch.model_dump(), f, indent=4, ensure_ascii=False)
            
        for incidente in relatorio_batch.incidentes:
            veredito = incidente.veredito.upper()
            alvo = incidente.id_alvo
            
            if veredito == "BLOQUEAR":
                self._mcp_tool_bloquear_ip(alvo)
            elif veredito == "MONITORAR":
                self._mcp_tool_adicionar_watchlist(alvo)
            else: 
                logger.info(f"✅ [MCP-Tool] O IP {alvo} é um falso positivo. Nenhuma ação tomada.")
                
        logger.info(f"=== [MCP] LOTE {num_lote} FINALIZADO E SALVO EM {caminho_arquivo} ===")

    # --- FERRAMENTAS DO MCP (TOOLS) ---
    def _mcp_tool_bloquear_ip(self, alvo: str):
        logger.warning(f"🚨 [MCP-Tool - FIREWALL] Executando DROP na borda da rede para o IP {alvo}!")

    def _mcp_tool_adicionar_watchlist(self, alvo: str):
        logger.info(f"👀 [MCP-Tool - SIEM] IP {alvo} adicionado à Watchlist para monitorização preventiva.")