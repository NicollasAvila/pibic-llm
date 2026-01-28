
```markdown
# Llama-Cyber: Automação de Análise de Logs de Segurança (SOC)

**Projeto de Pesquisa (PIBIC):** Avaliação de Small Language Models (SLMs) para Resposta a Incidentes em Ambientes Isolados.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![AI Status](https://img.shields.io/badge/Status-Em_Desenvolvimento-green)

## Sobre o Projeto

Este projeto visa desenvolver e validar um pipeline de Inteligência Artificial capaz de atuar como um **Analista de SOC Nível 1**. O foco principal é a utilização de modelos de linguagem menores (SLMs) rodando localmente para garantir a privacidade dos dados, analisando logs complexos de segurança (padrão SIEM Wazuh) e gerando relatórios de incidentes.

Para aferir a qualidade e a confiabilidade do modelo, utiliza-se a metodologia **LLM-as-a-Judge**, onde um modelo de grande porte (Llama-3-70B via Groq) atua como auditor, avaliando automaticamente a precisão técnica das respostas geradas pelo modelo local em comparação com o cenário real (Ground Truth).

## Metodologia e Fluxo de Trabalho

O pipeline automatizado consiste em três etapas sequenciais:

1.  **Geração de Dados Sintéticos (Data Factory)**
    * Responsável pela criação de logs sintéticos de alta fidelidade que simulam a estrutura aninhada do **Wazuh SIEM**.
    * Cobre cenários de ataque variados, como Ransomware, SQL Injection e Brute Force.
    * Modelo utilizado: `Llama-3.1-8B` (Base).

2.  **Inferência Local (O Analista)**
    * O modelo especialista processa o log bruto JSON.
    * Extrai Indicadores de Comprometimento (IoCs), classifica a ameaça e sugere ações de mitigação.
    * Modelo utilizado: `Llama-3-Cyber` (Fine-tuned/Local via Ollama).

3.  **Avaliação Automatizada (O Juiz)**
    * Compara a análise gerada pelo modelo local contra o gabarito do cenário original.
    * Atribui uma nota técnica (0-10) baseada em critérios de precisão, exatidão de IoC e formatação.
    * Modelo utilizado: `Llama-3.3-70B` (Via Groq API).

## Estrutura do Repositório

```text
├── dados/              # Armazena os datasets gerados (logs sintéticos)
├── resultados/         # Relatórios CSV com as notas e métricas da avaliação
├── src/                # Código fonte
│   ├── agente_juiz.py  # Script principal de avaliação (LLM-as-a-Judge)
│   └── gerar_dataset.py # Script gerador de logs Wazuh simulados
├── .env.example        # Modelo de variáveis de ambiente
├── .gitignore          # Arquivos ignorados pelo Git
├── README.md           # Documentação do projeto
└── requirements.txt    # Dependências do Python

```

## Instalação e Configuração

### Pré-requisitos

* Python 3.10 ou superior.
* [Ollama](https://ollama.com/) instalado e em execução.
* Chave de API da [Groq Cloud](https://console.groq.com/).

### Passo a Passo

1. **Clone o repositório:**
```bash
git clone [https://github.com/seu-usuario/seu-repo.git](https://github.com/seu-usuario/seu-repo.git)
cd seu-repo

```


2. **Configuração do Ambiente Virtual:**
```bash
python -m venv .venv
# Windows:
.\.venv\Scripts\activate
# Linux/Mac:
source .venv/bin/activate

```


3. **Instalação de Dependências:**
Crie um arquivo `requirements.txt` com o conteúdo abaixo e execute a instalação:
```text
ollama
groq
pandas
python-dotenv

```
Configuração do Modelo Customizado (Importante!)
O modelo fine-tuned (.gguf) é grande e não está incluído no repositório Git. Você deve baixá-lo separadamente.

Baixe o Modelo: Faça o download do arquivo llama-3-8b-instruct-cybersecurity.Q4_K_M.gguf (https://huggingface.co/cowWhySo/Llama-3-8B-Instruct-Cybersecurity-gguf/tree/main)

Organize a Pasta: Mova o arquivo baixado para dentro da pasta modelos_custom/ do projeto.

Registre o Modelo no Ollama: Execute os comandos abaixo para criar o agente local:

Bash
cd modelos_custom
ollama create llama3-cyber -f Modelfile.txt
cd ..

Comando de instalação:
```bash
pip install -r requirements.txt

```


4. **Variáveis de Ambiente:**
Renomeie o arquivo `.env.example` para `.env` e adicione sua chave:
```env
GROQ_API_KEY=gsk_sua_chave_aqui

```


5. **Modelos:**
Certifique-se de baixar o modelo base no Ollama:
```bash
ollama pull llama3.1

```



## Utilização

### 1. Gerar Novos Dados de Teste

Para criar um novo lote de logs simulados baseados em cenários de cibersegurança:

```bash
python src/gerar_dataset.py

```

*Resultado:* Criação/Atualização do arquivo `dados/dataset_sintetico.json`.

### 2. Executar a Avaliação

Para submeter o modelo local aos testes automatizados e obter o relatório de performance:

```bash
python src/agente_juiz.py

```

*Resultado:* Exibição das notas no terminal e geração do relatório detalhado em `resultados/relatorio_juiz.csv`.

## Segurança

Este projeto segue práticas de desenvolvimento seguro:

* Utilização de ambientes virtuais isolados.
* Os logs processados são inteiramente sintéticos, garantindo que nenhum dado sensível real seja exposto ou processado em nuvem.

---

**Instituição:** UEPA

```

```