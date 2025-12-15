
````markdown
# Benchmarking de SLMs para Resposta a Incidentes (PIBIC)

Este repositório contém os scripts e dados utilizados na pesquisa de Iniciação Científica (UEPA) sobre o uso de **Small Language Models (SLMs)** locais para a geração automática de Playbooks de Resposta a Incidentes de Cibersegurança.

O objetivo é validar a capacidade de modelos leves (rodando em CPU/Notebooks) de interpretar logs de segurança (JSON) e gerar planos de ação técnicos.

## 📋 Pré-requisitos

Para rodar este projeto, você precisará de:

1.  **Python 3.10+** instalado.
2.  **[Ollama](https://ollama.com/)** instalado e rodando em segundo plano (essencial para gerenciar os modelos).
3.  **Git** para clonar o repositório.

## 🚀 Instalação e Configuração

Siga os passos abaixo para preparar o ambiente de desenvolvimento.

### 1. Clonar o Repositório

```bash
git clone [URL_DO_SEU_REPOSITORIO]
cd [NOME_DA_PASTA]
````

### 2\. Criar e Ativar o Ambiente Virtual

Isolamos as dependências do projeto para evitar conflitos.

**No Windows (PowerShell):**

```bash
python -m venv .venv
.\.venv\Scripts\activate
```

**No Linux/Mac:**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3\. Instalar Dependências

Instale as bibliotecas Python necessárias (`ollama`, `litellm`, etc.):

```bash
pip install -r requirements.txt
```

### 4\. Baixar os Modelos de IA (Ollama)

Este projeto compara diferentes modelos. Execute os comandos abaixo no terminal para baixar os "cérebros" das IAs para sua máquina:

```bash
# Modelo leve (3B) - Para testes rápidos
ollama pull llama3.2

# Modelos robustos (7B/8B) - Para o benchmark comparativo
ollama pull llama3.1
ollama pull mistral
ollama pull qwen2.5
```

-----

## 📂 Estrutura do Projeto

  * **`dados/`**: Contém os arquivos de log brutos (`log1.json`, `log2.json`) simulando eventos de segurança (ex: detecção de PowerShell malicioso).
  * **`gerar_playbook.py`**: Script para teste rápido. Gera um único playbook no terminal usando o modelo mais leve (`llama3.2`).
  * **`comparar_modelos.py`**: Script de pesquisa. Executa uma bateria de testes com 3 modelos diferentes (`llama3.1`, `mistral`, `qwen2.5`), cronometra o tempo e salva os resultados em arquivos de texto.

-----

## 🧪 Como Rodar os Testes

Certifique-se de que o aplicativo **Ollama** está aberto e rodando perto do relógio do sistema.

### Teste 1: Validação Rápida (Terminal)

Para ver se o sistema está funcionando e gerar um playbook instantâneo na tela:

```bash
python gerar_playbook.py
```

*Modelo usado:* Llama 3.2 (3B)

### Teste 2: Benchmark Comparativo (Pesquisa)

Para rodar a comparação entre Llama 3.1, Mistral e Qwen. Este processo pode levar alguns minutos dependendo do hardware.

```bash
python comparar_modelos.py
```

**Saída esperada:**
O script criará arquivos `.txt` na pasta raiz com o nome de cada modelo (ex: `resultado_mistral.txt`), contendo:

  * O tempo total de execução.
  * O Playbook gerado pelo modelo.

-----

## 📊 Resultados Preliminares (Notebook)

Testes realizados em ambiente de Notebook (CPU):

| Modelo | Parâmetros | Tempo Médio | Observação |
| :--- | :--- | :--- | :--- |
| **Llama 3.2** | 3B | \~2.5 min | Rápido, ideal para dev. |
| **Qwen 2.5** | 7B | \~6.1 min | Melhor performance entre os 7B. |
| **Mistral** | 7B | \~6.2 min | Respostas consistentes. |
| **Llama 3.1** | 8B | \~6.2 min | Padrão de mercado. |

-----



<!-- end list -->

```
```