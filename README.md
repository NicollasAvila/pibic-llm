# Llama-Cyber: Arquitetura Híbrida de Resposta a Incidentes (Edge Computing)

**Projeto de Pesquisa (PIBIC):** Avaliação de Small Language Models (SLMs) para Resposta a Incidentes em Ambientes com Restrição de Hardware (16GB RAM).

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Llama.cpp](https://img.shields.io/badge/Engine-llama.cpp-orange)
![FAISS](https://img.shields.io/badge/VectorDB-FAISS-yellow)
![Status](https://img.shields.io/badge/Status-Refatoração_Arquitetural-green)

## Sobre o Projeto

Este projeto implementa uma arquitetura de cibersegurança de nível corporativo (SOC Nível 1) desenhada estritamente para operar na borda da rede (**Edge Computing**). O maior desafio resolvido por esta pesquisa é o custo computacional: evitar a "explosão de tokens" e o esgotamento de memória ao analisar milhares de logs por segundo em hardwares de consumo padrão (16GB RAM e GPU AMD RX 6600).

Para viabilizar isso, o projeto abandona a leitura "força bruta" de logs brutos por IA e adota um **Pipeline Híbrido em 3 Camadas**, unindo triagem determinística (Regex), enriquecimento espaço-temporal (RAG) e inferência neural quantizada em 4-bits.

## Arquitetura do Sistema

O fluxo de dados foi desenhado para garantir latência ultrabaixa e zero alucinação de formato:

* **Fase 1: Funil de Ingestão e Preparação (Tempo Real)**
  * **Camada 1 (Triagem Determinística):** Uso de scripts Python com Expressões Regulares (Regex) para filtrar e descartar até 90% do tráfego interno benigno.
  * **Camada 2 (Tradução Semântica e RAG):** O log bruto restante é condensado em uma sentença de texto curta. O script realiza uma busca ultrarrápida em memória via **FAISS** (Threat Intelligence) e anota o log com *Tags Espaço-Temporais* (ex: `[MADRUGADA] [IP_EXTERNO]`), poupando a IA de processar dados inúteis.

* **Fase 2: Inferência Agêntica (Tempo Real)**
  * **Camada 3 (SLM Especialista):** Modelos de 1.5B a 3B de parâmetros (ex: Qwen2.5 ou Llama-3.2) quantizados em formato `GGUF` (4-bits). Recebem blocos de logs traduzidos (*Batching*) e executam ferramentas simuladas (*Model Context Protocol - MCP*) para emitir o Playbook de Resposta estruturado em JSON.

* **Fase 3: MLOps e Auditoria (Offline)**
  * **LLM-as-a-Judge:** Um modelo de 70B (Groq API) atua como auditor cego, avaliando a acurácia semântica do modelo local contra o cenário real (Ground Truth).
  * **Continuous Training (QLoRA):** Os erros identificados pelo juiz retroalimentam o sistema para ajuste fino do SLM (Diferenciação de Contexto), zerando gradativamente os falsos positivos.

## Estrutura do Repositório

```text
pibic-llm/
├── dados/
│   ├── raw/                  # Logs originais do Firewall/SIEM
│   └── vector_db/            # Índices do FAISS (Base de Conhecimento RAG)
├── resultados/               # Relatórios CSV (Métricas de Avaliação do Juiz)
├── src/
│   ├── core/                 # Pipeline de Produção (Tempo Real)
│   │   ├── camada1_triagem.py
│   │   ├── camada2_tradutor.py
│   │   └── camada3_agente.py
│   ├── evaluation/           # Pipeline de Treino e Validação (Offline)
│   │   ├── juiz_70b.py
│   │   └── gerar_dataset.py
│   ├── config.py             # Prompts e Variáveis de Ambiente
│   └── main_pipeline.py      # Orquestrador das Camadas 1, 2 e 3
├── .env.example
├── requirements.txt
├── soc.bat                   # CLI Interativo para Windows
└── README.md
```

## Como Rodar o Projeto

### Pré-requisitos
* Python 3.10 ou superior.
* Chave de API da [Groq Cloud](https://console.groq.com/) (Para o LLM Juiz).

### 1. Instalação Básica

Clone o repositório, ative o ambiente virtual (`.venv` ou `venv`) e instale os requerimentos:

```bash
git clone https://github.com/NicollasAvila/pibic-llm.git
cd pibic-llm

# Crie e ative o ambiente virtual (Windows)
python -m venv .venv
.\.venv\Scripts\activate

# Instale os pacotes
pip install -r requirements.txt
```

### 2. Configuração do Modelo e API

1. Renomeie o arquivo `.env.example` para `.env` e coloque sua chave Groq (`GROQ_API_KEY=sua_chave_aqui`).
2. Garanta que o LLM local está rodando (via Ollama na porta padrão `11434` ou baixando um `.gguf` conforme o mapeamento no `src/config.py`).

### 3. Operando o SOC via Painel Interativo

Para testar as camadas e visualizar dados sem entrar em linhas de comando longas, basta iniciar o Menu Interativo na raiz do projeto (apenas para Windows):

```cmd
soc.bat
```

No menu, selecione entre:
* `[1] Rodar o Pipeline Principal:` Inicia o `main_pipeline.py`. Lê velozmente os logs do firewall/siem na pasta `dados/raw/`, faz a triagem por regex (Camada 1), busca ameaças no FAISS (Camada 2) e repassa as anomalias num sistema de fila para o LLM Local (Camada 3) julgar e emitir vereditos.
* `[2] Abrir o Dashboard:` Sobe o servidor Streamlit web (`app_dashboard.py`) para você visualizar estatísticas globais graficamente, relatórios e vereditos de tráfego.
* `[3] Rodar a Auditoria:` Chama o Juiz 70B (Groq) no `juiz_70b.py` para avaliar se os julgamentos do LLM local foram bons ou ruins (Pipeline de ML/Treinamento contínuo).
* `[4] Atualizar Base de Conhecimento:` Gera um novo índice RAG caso você adicione novos `.txt` ou `.pdf` de regras corporativas.
