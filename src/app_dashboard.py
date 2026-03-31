import streamlit as st
import json
import os
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from pathlib import Path

st.set_page_config(page_title="SOC AI - Sentinel Pibic", layout="wide", initial_sidebar_state="expanded")

# --- LEITURA SEGURA DOS ARQUIVOS E A/B TESTING ---
from config import RESULTADOS_DIR_ROOT, ARQUIVO_BLACKLIST, ARQUIVO_WATCHLIST

# 1. Encontrar todos os modelos (subpastas) disponíveis
try:
    modelos_disponiveis = [d.name for d in RESULTADOS_DIR_ROOT.iterdir() if d.is_dir()]
except FileNotFoundError:
    modelos_disponiveis = []

if not modelos_disponiveis:
    modelos_disponiveis = ["llama3.2"] # Fallback

st.sidebar.header("🧪 Configurações do Experimento (A/B Test)")
modelo_selecionado = st.sidebar.selectbox(
    "Selecione o Modelo para Análise:", 
    sorted(modelos_disponiveis, reverse=True)
)

# 2. Apontar o diretório de leitura restrito para o modelo escolhido!
RESULTADOS_DIR_DINAMICO = RESULTADOS_DIR_ROOT / modelo_selecionado

def carregar_json(nome_arquivo):
    caminho = RESULTADOS_DIR_DINAMICO / nome_arquivo
    if caminho.exists():
        try:
            with open(caminho, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None

def carregar_jsonl(nome_arquivo):
    caminho = RESULTADOS_DIR_DINAMICO / nome_arquivo
    dados = []
    if caminho.exists():
        with open(caminho, "r", encoding="utf-8") as f:
            for linha in f:
                linha = linha.strip()
                if linha:
                    try: dados.append(json.loads(linha))
                    except: pass
    return dados if dados else None

def ler_linhas_arquivo(caminho):
    if caminho.exists():
        with open(caminho, "r", encoding="utf-8") as f:
            return f.readlines()
    return []

# Carregamento de Dados em Tempo Real (Isolados na gaveta do modelo com tolerância a falhas O(1))
dados_playbook = carregar_jsonl("playbook_global.jsonl")
dados_memoria = carregar_json("memoria_global_ips.json")
dados_juiz = carregar_json("auditoria_global.json")
dados_metricas = carregar_jsonl("metricas_desempenho.jsonl")

# AS Listas de Borda (SIEM e Firewall) continuam sendo globais
linhas_blacklist = ler_linhas_arquivo(ARQUIVO_BLACKLIST)
linhas_watchlist = ler_linhas_arquivo(ARQUIVO_WATCHLIST)

# --- CABEÇALHO E TÍTULO ---
st.title("🛡️ Centro de Operações de Segurança Autônomo (SOC 24/7)")
st.markdown(f"**Pesquisa PIBIC:** Arquitetura Assíncrona com IA na Borda, RAG e Triagem | 🧠 **Modelo Avaliado:** `{modelo_selecionado}`")
st.divider()

# --- PREPARAÇÃO DE DADOS PRINCIPAIS ---
df_playbook = pd.DataFrame()
decisoes_em_cache = 0

if dados_playbook:
    df_playbook = pd.DataFrame(dados_playbook)
    if 'justificativa' in df_playbook.columns:
        df_playbook['veio_do_cache'] = df_playbook['justificativa'].apply(
            lambda x: "Sim" if isinstance(x, str) and "CACHE" in x else "Não"
        )
        decisoes_em_cache = len(df_playbook[df_playbook['veio_do_cache'] == 'Sim'])

df_metrics = pd.DataFrame(dados_metricas) if dados_metricas else pd.DataFrame()
tps_medio = df_metrics.get('tps', pd.Series([0])).mean() if not df_metrics.empty else 0.0

drops_fw_nativo = int(df_metrics.get('drops_firewall', pd.Series([0])).sum()) if not df_metrics.empty else 0
drops_ia_ativo = int(df_metrics.get('drops_ia_ativo', pd.Series([0])).sum()) if not df_metrics.empty else 0
drops_totais = drops_fw_nativo + drops_ia_ativo

# --- KPIS TOP LEVEL ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("🌐 Perfis Mapeados na RAM", len(dados_memoria) if dados_memoria else 0)

# Métrica Composta do Novo IPS (A/B Test)
col2.metric("🛑 Conexões Rejeitadas (Borda)", drops_totais, f"{drops_ia_ativo} cortadas pela IA", delta_color="normal")

col3.metric("♻️ Decisões em Cache (GPU Livre)", decisoes_em_cache)
col4.metric("⚡ Velocidade do Motor SLM", f"{tps_medio:.1f} TPS" if tps_medio > 0 else "Aguardando...")
st.markdown("<br>", unsafe_allow_html=True)

# --- ABAS E NAVEGAÇÃO ---
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "🎯 Playbook (Vereditos)", 
    "🕸️ Triagem Espaço-Tempo", 
    "🧱 Fronteira Segura", 
    "📈 Desempenho e Borda", 
    "⚖️ Auditoria do Juiz IA"
])

# ==========================================
# ABA 1: PLAYBOOK DE DECISÕES
# ==========================================
with tab1:
    st.subheader("Histórico Global de Decisões")
    if not df_playbook.empty:
        c1, c2 = st.columns([1, 2])
        
        with c1:
            # Gráfico de Donut (Verdicts)
            contagem = df_playbook['veredito'].value_counts().reset_index()
            contagem.columns = ['Veredito', 'Quantidade']
            
            color_map = {'BLOQUEAR': '#ff4b4b', 'MONITORAR': '#ffa421', 'FALSO_POSITIVO': '#00c04b'}
            
            fig_pizza = px.pie(contagem, values='Quantidade', names='Veredito', 
                               title='Proporção de Resposta a Incidentes', hole=0.5,
                               color='Veredito', color_discrete_map=color_map)
            fig_pizza.update_traces(textposition='inside', textinfo='percent+label', marker=dict(line=dict(color='#0e1117', width=2)))
            fig_pizza.update_layout(showlegend=False)
            st.plotly_chart(fig_pizza, use_container_width=True)
            
        with c2:
            # Painel Analítico
            filtros = st.multiselect("Filtrar por Veredito Estratégico:", options=df_playbook['veredito'].unique(), default=df_playbook['veredito'].unique())
            df_filtrado = df_playbook[df_playbook['veredito'].isin(filtros)]
            
            colunas_exibicao = ['id_alvo', 'veredito', 'is_red_team', 'veio_do_cache', 'analise_contexto', 'justificativa', 'dica_rag']
            colunas_reais = [c for c in colunas_exibicao if c in df_filtrado.columns]
            
            # SIDEBAR: Eficácia do Teste Duplo-Cego do Red Team
            if 'is_red_team' in df_playbook.columns:
                df_red = df_playbook[df_playbook['is_red_team'] == True]
                df_red_blocked = df_red[df_red['veredito'] == 'BLOQUEAR']
                if not df_red.empty:
                    taxa = (len(df_red_blocked) / len(df_red)) * 100
                    st.sidebar.divider()
                    st.sidebar.metric(f"🎯 Red Team True Positives", f"{taxa:.1f}%", f"{len(df_red_blocked)}/{len(df_red)} ataques bloqueados")
                    st.sidebar.caption("Eficácia da IA frente às anomalias cegas do Red Team escondidas no pipeline.")
            
            # Utilizando data_editor para permitir leitura longa sem cortes e design moderno
            st.data_editor(
                df_filtrado[colunas_reais],
                column_config={
                    "id_alvo": st.column_config.TextColumn("IP / Alvo", width="small"),
                    "veredito": st.column_config.TextColumn("Ação Final", width="small"),
                    "is_red_team": st.column_config.CheckboxColumn("Alerta Falso?", width="small"),
                    "veio_do_cache": st.column_config.TextColumn("Cache", width="small"),
                    "analise_contexto": st.column_config.TextColumn("Cadeia de Pensamento (CoT)", width="large"),
                    "justificativa": st.column_config.TextColumn("Justificativa Oficial", width="medium"),
                    "dica_rag": st.column_config.TextColumn("Regra Corporativa RAG", width="medium"),
                },
                use_container_width=True, hide_index=True, height=400, disabled=True
            )
    else:
        st.info("Nenhuma decisão computada pela arquitetura até o momento.")

# ==========================================
# ABA 2: MEMÓRIA COMPORTAMENTAL E TRIAGEM
# ==========================================
with tab2:
    st.subheader("Matriz de Risco (Triagem Espaço-Temporal)")
    st.markdown("A Camada 1 do motor traduz a frequência (Tempo) e a variância dos alvos (Espaço) em coordenadas dentro de um grafo de ataque, focando a Llama apenas onde há comportamento anômalo.")
    
    if dados_memoria:
        lista = []
        for ip, info in dados_memoria.items():
            alvos = len(info.get("alvos_dst", []))
            eventos = info.get("total_eventos", 0)
            
            if alvos >= 3: 
                status = "Dispersão Espacial (Anomalia)"
                cor = "#ff4b4b"
            elif eventos >= 100: 
                status = "Volume Temporal (Burst)"
                cor = "#ffa421"
            else: 
                status = "Tráfego Padrão"
                cor = "#00c04b"
                
            lista.append({
                "Nó de Origem": ip, 
                "Alvos Conectados": alvos, 
                "Volume Arestas": eventos,
                "Classificação": status,
                "Cor": cor
            })
            
        df_mem = pd.DataFrame(lista)
        
        c_graf, c_tab = st.columns([1.5, 1])
        with c_graf:
            fig_bolha = px.scatter(df_mem, x="Volume Arestas", y="Alvos Conectados",
                                   size="Volume Arestas", color="Classificação",
                                   hover_name="Nó de Origem", 
                                   title="Cadeias de Comportamento Anômalo Identificadas",
                                   color_discrete_map={"Dispersão Espacial (Anomalia)": "#ff4b4b", "Volume Temporal (Burst)": "#ffa421", "Tráfego Padrão": "#00c04b"})
            # Ajuste de layout militar escuro do Plotly
            fig_bolha.update_layout(xaxis_title="Intensidade Temporal (Requisições)", yaxis_title="Dispersão Espacial (IPs Destino Distintos)")
            # Evitar bolhas muito pequenas
            fig_bolha.update_traces(marker=dict(sizemin=8))
            st.plotly_chart(fig_bolha, use_container_width=True)
            
        with c_tab:
            st.dataframe(df_mem.drop(columns=["Cor"]).sort_values(by="Volume Arestas", ascending=False), use_container_width=True, hide_index=True)
    else:
        st.info("O ambiente ainda não capturou a construção do Grafo.")

# ==========================================
# ABA 3: FRONTEIRA E FIREWALL
# ==========================================
with tab3:
    st.subheader("Mitigação Ativa e Firewall Dinâmico (IPS)")
    st.markdown("A partir da implementação IPS, a Inteligência Artificial gerencia o Firewall em malha fechada. IPs condenados geram Early-Drops instantâneos via Hashmap O(1).")
    c_fw1, c_fw2 = st.columns(2)
    with c_fw1:
        st.error(f"💣 Invasores Isolados pela IA (Blacklist Dinâmica) - {len(linhas_blacklist)} Ativos no TTL")
        if linhas_blacklist:
            for linha in reversed(linhas_blacklist[-25:]): st.code(linha.strip(), language="bash")
        else:
            st.info("Nenhuma IP inserido no purgatório ainda pelo LLM.")
    with c_fw2:
        st.warning(f"🔭 Relatórios de Carga Total - Early-Drops")
        st.metric("Descartes Nativos (Assinatura L4)", drops_fw_nativo)
        st.metric("Descartes Inteligentes (Cérebro L7)", drops_ia_ativo)
        st.info("A Defesa Ativa poupou a arquitetura de reprocessar todas essas requisições criminosas acima.")

# ==========================================
# ABA 4: DESEMPENHO E TELEMETRIA (PIBIC)
# ==========================================
with tab4:
    st.subheader("Análise de Gargalo Computacional em Edge")
    if not df_metrics.empty:
        col_graf1, col_graf2 = st.columns(2)
        with col_graf1:
            if "tempo_c1_seg" in df_metrics.columns and "tempo_c2_seg" in df_metrics.columns:
                df_tempos = pd.DataFrame({
                    "Lote Processado": df_metrics["lote"],
                    "Algoritmo Espaço-Temporal (C1)": df_metrics["tempo_c1_seg"] * 1000,
                    "Busca Vetorial RAG Semântico (C2)": df_metrics["tempo_c2_seg"] * 1000
                }).melt(id_vars=["Lote Processado"], var_name="Componente Pré-Inferência", value_name="Tempo Alocado (ms)")
                fig_tempos = px.line(df_tempos, x="Lote Processado", y="Tempo Alocado (ms)", color="Componente Pré-Inferência", title="Latência Externa na Borda (Milissegundos)", markers=True)
                st.plotly_chart(fig_tempos, use_container_width=True)
                
        with col_graf2:
            if "total_duration" in df_metrics.columns and "tempo_io_disco" in df_metrics.columns:
                df_llm = pd.DataFrame({
                    "Lote Processado": df_metrics["lote"],
                    "Inteligência SLM/GPU (s)": df_metrics["total_duration"],
                    "Gargalo SSD/RAM (s)": df_metrics["tempo_io_disco"]
                }).melt(id_vars=["Lote Processado"], var_name="Métrica Física", value_name="Tempo (Segundos)")
                
                fig_llm = px.area(df_llm, x="Lote Processado", y="Tempo (Segundos)", color="Métrica Física", 
                                  title="Gargalo de I/O vs Processamento Neural (Impacto Real)", markers=True)
                # Cores contrastantes (Vermelho pro Gargalo, Verde pra IA)
                fig_llm.update_traces(mode="lines+markers")
                st.plotly_chart(fig_llm, use_container_width=True)
            elif "total_duration" in df_metrics.columns:
                fig_llm = px.area(df_metrics, x="lote", y="total_duration", title="Custo de Carga da GPU (Camada 3) por Lote (Segundos)", markers=True)
                fig_llm.update_traces(line_color="#43a047", fillcolor="rgba(67, 160, 71, 0.4)")
                st.plotly_chart(fig_llm, use_container_width=True)
                
        # Gráfico Gauge para TPS
        if tps_medio > 0:
            c1, c2, c3 = st.columns([1,2,1])
            with c2:
                fig_gauge = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = tps_medio,
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Vazão da Inteligência Artificial (TPS)", 'font': {'size': 20}},
                    gauge = {'axis': {'range': [None, 60], 'tickwidth': 1, 'tickcolor': "darkblue"},
                             'bar': {'color': "#0088ff"},
                             'bgcolor': "white",
                             'borderwidth': 2,
                             'bordercolor': "gray",
                             'steps': [
                                 {'range': [0, 15], 'color': "#111111"},
                                 {'range': [15, 30], 'color': "#222222"},
                                 {'range': [30, 60], 'color': "#333333"}]}
                ))
                # Fundo transparente caso use Streamlit Dark Theme
                fig_gauge.update_layout(paper_bgcolor="rgba(0,0,0,0)", font={'color': "white", 'family': "Arial"})
                st.plotly_chart(fig_gauge, use_container_width=True)
    else:
        st.info("O módulo de coleta de telemetria ainda aguarda a conclusão do primeiro lote na Camada 1.")

# ==========================================
# ABA 5: AUDITORIA DO JUIZ LLM
# ==========================================
with tab5:
    st.subheader("Crivo Empírico e Validação Rigorosa (LLM-as-a-Judge)")
    
    with st.expander("📖 As OITO (8) Diretrizes de Julgamento", expanded=False):
        st.markdown("""
        **Como a IA Avaliadora penaliza ou corrobora as decisões do nosso Motor Principal (Llama 3.2):**
        1. 🔬 **Fidelidade Factual (Factual Fidelity):** Verifica se a Camada 3 extraiu os IPs e as portas corretamente do log bruto, sem adicionar contextos inexistentes ou ignorar evidências claras. Pune pesadamente alucinações matemáticas da LLM.
        2. 🧠 **Raciocínio Lógico (Logical Reasoning):** Analisa a *Chain-of-Thought* (A coluna *Cadeia de Pensamento*). A SLM articulou de forma irrefutável o motivo temporal ou espacial antes de entregar o veredito? Ela pulou conclusões lógicas sobre a real ameaça mitigada?
        3. 🎯 **Acurácia da Decisão (Decision Accuracy):** O veredito (Bloqueio vs Monitoramento vs Falso Positivo) reflete apropriadamente o risco calculado? Tráfego legal de usuários de rede deve gerar *FALSO_POSITIVO* e malwares óbvios merecem *BLOQUEAR* baseado puramente nos dados em mãos.
        4. 🛡️ **Adesão à Instrução (Instruction Adherence):** Avalia se a IA se atrelou às saídas de formatação Pydantic, seguindo as diretrizes Sistêmicas (System Prompts). Modelos indisciplinados respondem amigavelmente e quebram as APIs JSON. Nota alta representa formatação estrita como determinista de máquina.
        """)
        
    if dados_juiz:
        df_aud = pd.DataFrame(dados_juiz).rename(columns={"ip": "id_alvo"})
        
        c_radar, c_box = st.columns(2)
        
        with c_radar:
            # Pegando as médias de eficácia globais
            media_fid = df_aud['fidelidade_factual'].mean() if 'fidelidade_factual' in df_aud else 0
            media_acu = df_aud['acuracia_decisao'].mean() if 'acuracia_decisao' in df_aud else 0
            media_rac = df_aud['qualidade_raciocinio'].mean() if 'qualidade_raciocinio' in df_aud else 0
            media_ade = df_aud['adesao_instrucao'].mean() if 'adesao_instrucao' in df_aud else 0
            
            df_radar = pd.DataFrame({
                'Métrica de Estresse': ['Fidelidade Factual', 'Acurácia Final', 'Raciocínio CoT', 'Adesão Sistêmica'],
                'Desempenho (0-10)': [media_fid, media_acu, media_rac, media_ade]
            })
            
            fig_rad = px.line_polar(df_radar, r='Desempenho (0-10)', theta='Métrica de Estresse', line_close=True, 
                                    title="Assinatura Qualitativa do Motor de Borda (Raio X)", range_r=[0, 10])
            fig_rad.update_traces(fill='toself', line_color='#9100c0', fillcolor='rgba(145, 0, 192, 0.4)')
            st.plotly_chart(fig_rad, use_container_width=True)
            
        with c_box:
            # Gráfico de Calibração Confiança vs Acurácia
            if not df_playbook.empty and 'nivel_confianca' in df_playbook.columns:
                df_cruz = pd.merge(df_playbook, df_aud, on="id_alvo", how="inner")
                if not df_cruz.empty:
                    df_cruz['nivel_confianca'] = pd.Categorical(df_cruz['nivel_confianca'], categories=['BAIXA', 'MEDIA', 'ALTA'], ordered=True)
                    fig_box = px.box(df_cruz, x='nivel_confianca', y='acuracia_decisao', color='nivel_confianca',
                                 title="Curva de Calibração: Certeza Projetada vs. Auditoria Real",
                                 points="all", color_discrete_map={'BAIXA': '#ff4b4b', 'MEDIA': '#ffa421', 'ALTA': '#00c04b'})
                    fig_box.update_yaxes(range=[0, 11])
                    st.plotly_chart(fig_box, use_container_width=True)
                else:
                    st.info("Pendente: Cruze de Dados de Avaliação para gerar a Projeção de Confiança.")

        # Recentes Pareceres de Auditoria do Juiz
        st.divider()
        st.subheader("Auditorias Minuciosas Recentes")
        for av in reversed(dados_juiz[-5:]):
            alvo = av.get('ip', 'N/A')
            nota = av.get('acuracia_decisao', 0)
            
            if nota >= 8: st_col = "🟢"
            elif nota >= 5: st_col = "🟡"
            else: st_col = "🔴"
            
            st.markdown(f"**Alvo Inspecionado:** `{alvo}` | Classificação Final Lógica: **{st_col} {nota}/10**")
            st.info(f"**Parecer Discursivo Oficial do Juiz Nuvem:** *{av.get('parecer_juiz', 'Sem comentários detalhados adicionais')}*")
            
    else:
        st.info("A auditoria analítica paralela (Modelo Grande em Nuvem) ainda não gerou notas qualitativas.")