````markdown
# Geração Automática de Planos de Ação para Resposta a Ataques de Rede (PIBIC)

Este é o repositório oficial do projeto de Iniciação Científica (PIBIC/UEPA) focado no desenvolvimento de uma metodologia baseada em IA Generativa para resposta a incidentes de cibersegurança.

## 🚀 Configuração do Ambiente de Desenvolvimento

Para garantir que todos os membros da equipe tenham um ambiente idêntico, siga estes passos.

### 1. Pré-requisitos

* **Python:** Tenha o [Python](https://www.python.org/downloads/) (versão 3.10 ou superior) instalado.
* **Git:** Tenha o [Git](https://git-scm.com/downloads) instalado.
* **VS Code:** Recomendamos o [Visual Studio Code](https://code.visualstudio.com/) como IDE com a extensão oficial "Python".

### 2. Clonar o Repositório

Primeiro, clone este repositório para o seu computador:

```bash
git clone [URL_DO_SEU_REPOSITORIO_AQUI]
cd [NOME_DO_SEU_REPOSITORIO]
````

### 3\. Criar o Ambiente Virtual

Usaremos um ambiente virtual (`.venv`) para isolar as dependências do projeto.

```bash
# Crie o ambiente virtual
python -m venv .venv
```

### 4\. Ativar o Ambiente Virtual

Você deve ativar o ambiente **toda vez** que for trabalhar no projeto.

**No Windows (PowerShell/CMD):**

```bash
.\.venv\Scripts\activate
```

**No macOS / Linux (Bash/Zsh):**

```bash
source .venv/bin/activate
```

(Você saberá que funcionou pois o nome `(.venv)` aparecerá no seu terminal).

### 5\. Instalar as Dependências

Com o ambiente ativo, instale todas as bibliotecas necessárias usando o arquivo `requirements.txt`.

```bash
# Garante que o pip (gerenciador de pacotes) está atualizado
pip install --upgrade pip

# Instala todas as bibliotecas do projeto
pip install -r requirements.txt
```

### 6\. Pronto\!

Seu ambiente está configurado. As bibliotecas instaladas incluem:

  * `torch` e `transformers` (para carregar os LLMs)
  * `langchain` e `llama-index` (para implementar o RAG)
  * `faiss-cpu` e `chromadb` (bancos vetoriais para o RAG)
  * `pandas` (para manipulação de dados)
  * `jupyter` (para notebooks de experimentação)

<!-- end list -->

```
```
