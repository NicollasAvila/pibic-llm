@echo off
:: Muda a codificação para aceitar acentos no terminal
chcp 65001 >nul

:menu
cls
echo =======================================================
echo         SOC AUTÔNOMO - MENU DE OPERAÇÕES
echo =======================================================
echo [1] 🚀 Rodar o Pipeline Principal (Red Team + Triagem)
echo [2] 📊 Abrir o Dashboard (Streamlit)
echo [3] ⚖️  Rodar a Auditoria (Juiz 70B)
echo [4] 🧠 Atualizar Base de Conhecimento (FAISS RAG)
echo [0] ❌ Sair
echo =======================================================
set /p opcao="Escolha um comando: "

:: Verifica se o ambiente virtual existe antes de ativar
if exist ".venv\Scripts\activate.bat" (
    call .venv\Scripts\activate.bat
) else (
    echo [AVISO] Ambiente virtual .venv nao encontrado!
)

if "%opcao%"=="1" goto pipeline
if "%opcao%"=="2" goto dashboard
if "%opcao%"=="3" goto juiz
if "%opcao%"=="4" goto faiss
if "%opcao%"=="0" goto fim

:: Se digitar algo errado, volta ao menu
goto menu

:pipeline
echo.
echo Iniciando a analise de logs e injecao em memoria...
python src\main_pipeline.py
echo.
pause
goto menu

:dashboard
echo.
echo Iniciando o servidor web do Dashboard...
cd src
python -m streamlit run d:/pibic-llm/src/app_dashboard.py
goto menu

:juiz
echo.
echo Iniciando LLM-as-a-Judge para avaliar as decisoes...
:: Ajuste o caminho abaixo se o seu juiz_70b.py estiver noutra pasta
python D:\pibic-llm\src\core\juiz_70b.py
echo.
pause
goto menu

:faiss
echo.
echo Recriando o indice vetorial do RAG...
python src\core\gerar_indice_faiss.py
echo.
pause
goto menu

:fim
echo.
echo Encerrando o terminal do SOC...