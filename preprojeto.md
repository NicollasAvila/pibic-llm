# Pré-Projeto: Llama-Cyber

## 1. Identificação do Projeto
**Título:** Llama-Cyber: Automação de Análise de Logs de Segurança com Modelos de Linguagem Pequenos em Ambientes Isolados.

## 2. Objetivo Geral
Desenvolver um pipeline de Inteligência Artificial projetado para atuar como um **Analista de SOC (Security Operations Center) Nível 1 automatizado**. [cite_start]O objetivo central é validar a eficácia de *Small Language Models* (SLMs) operando localmente para analisar logs de segurança complexos, priorizando a privacidade dos dados ao realizar o processamento sem conexão com serviços externos[cite: 3, 4].

---

## 3. Arquitetura da Solução e Fluxograma

[cite_start]A arquitetura do sistema é composta por três componentes sequenciais que garantem a geração, análise e validação dos dados de segurança[cite: 5, 6].

### Fluxo de Processamento de Dados

**1. Entrada (Geração de Dados)**
> [cite_start]O sistema inicia com a criação de cenários de ataque simulados para treinar e testar a ferramenta[cite: 6].
* **Ação:** Gera logs no padrão Wazuh (SIEM).
* **Cenários:** Ransomware, SQL Injection e Brute Force.
* [cite_start]**Tecnologia:** Modelo Llama-3.1-8B[cite: 11].

⬇

**2. Processamento (O Analista Local)**
> [cite_start]O núcleo do projeto, onde a análise ocorre em ambiente isolado (offline) para garantir privacidade[cite: 4, 7].
* **Ação:** Processa os logs, extrai Indicadores de Comprometimento (IoCs), classifica ameaças e sugere mitigação.
* [cite_start]**Tecnologia:** Modelo Llama-3-Cyber (Fine-tuned) rodando via Ollama[cite: 7, 10].

⬇

**3. Saída e Validação (O Auditor)**
> [cite_start]Verificação da qualidade da análise realizada pelo modelo local[cite: 8].
* **Ação:** Compara a análise local com o gabarito esperado e atribui uma nota técnica (0-10).
* [cite_start]**Tecnologia:** Modelo Llama-3.3-70B (LLM-as-a-Judge) acessado via Groq API[cite: 8, 10].

---

## 4. Detalhamento Técnico dos Componentes

### Componente 1: Gerador de Dataset Sintético
Este módulo é responsável por criar a base de dados necessária para o estudo. [cite_start]Ele utiliza o modelo **Llama-3.1-8B** para simular logs de ferramentas SIEM (Wazuh) baseados em ataques cibernéticos reais[cite: 6, 11].

### Componente 2: Analista de SOC Local (Offline)
Este é o foco da validação científica. Utiliza o modelo **Llama-3-Cyber** customizado. [cite_start]Ele roda localmente através do **Ollama**, garantindo que nenhum dado sensível do log saia da infraestrutura local[cite: 7].

### Componente 3: Auditor Automático (LLM-as-a-Judge)
Para escalar a avaliação sem depender de revisão humana manual, o projeto utiliza um modelo de grande porte (**Llama-3.3-70B**) hospedado na nuvem (via **Groq**). [cite_start]Ele atua como juiz, avaliando a precisão técnica das respostas do modelo local[cite: 8, 10].

---

## 5. Stack Tecnológica
[cite_start]O desenvolvimento do projeto utiliza as seguintes tecnologias[cite: 10, 11]:

* **Linguagem:** Python 3.10+.
* **Execução Local:** Ollama.
* **Execução Nuvem (Juiz):** API Groq.
* **Dados:** Biblioteca `pandas`.
* **Configuração:** `python-dotenv`.
* **Modelos:** Llama-3.1-8B, Llama-3-Cyber, Llama-3.3-70B.

## 6. Justificativa Científica
[cite_start]O projeto busca responder se modelos menores (SLMs) conseguem substituir ferramentas comerciais em tarefas de triagem inicial, mantendo a acurácia técnica e garantindo a segurança de dados em ambientes desconectados[cite: 14].