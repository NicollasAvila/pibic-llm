import streamlit as st
import json
import os
import pandas as pd
import plotly.express as px

st.set_page_config(page_title="SOC AI - Sentinel", layout="wide", initial_sidebar_state="collapsed")

# --- LEITURA SEGURA DOS ARQUIVOS (Usando "../" para voltar uma pasta) ---
def carregar_json(caminho):
    if os.path.exists(caminho):
        try:
            with open(caminho, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None

def ler_linhas_arquivo(caminho):
    if os.path.exists(caminho):
        with open(caminho, "r", encoding="utf-8") as f:
            return f.readlines()
    return []

dados_playbook = carregar_json("../resultados/playbook_global.json")
dados_memoria = carregar_json("../resultados/memoria_global_ips.json")
dados_juiz = carregar_json("../resultados/auditoria_global.json")
linhas_blacklist = ler_linhas_arquivo("../resultados/blacklist_firewall.txt")
linhas_watchlist = ler_linhas_arquivo("../resultados/watchlist_siem.txt")

# --- CABEÇALHO ---
st.title("Centro de Operações de Segurança Autônomo")
st.markdown("**Pesquisa PIBIC:** Avaliação de Raciocínio Espaço-Temporal com IA na Borda (Edge SLM) e RAG")
st.divider()

# Processamento prévio do Playbook para Extrair Auto-Correção
df_playbook = pd.DataFrame()
auto_correcoes = 0
if dados_playbook:
    df_playbook = pd.DataFrame(dados_playbook)
    if 'justificativa' in df_playbook.columns:
        df_playbook['auto_corrigido'] = df_playbook['justificativa'].apply(
            lambda x: "Sim" if isinstance(x, str) and "Auto-Correção" in x else "Não"
        )
        auto_correcoes = len(df_playbook[df_playbook['auto_corrigido'] == 'Sim'])

# --- KPIs ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Perfis Mapeados (Nós do Grafo)", len(dados_memoria) if dados_memoria else 0)
col2.metric("Ameaças Bloqueadas (DROP)", len(linhas_blacklist))
col3.metric("Reflexões (Auto-Correções)", auto_correcoes)
col4.metric("Motor de Inferência Ativo", "Llama 3.1 8B")
st.markdown("<br>", unsafe_allow_html=True)

# --- ABAS ---
tab1, tab2, tab3, tab4 = st.tabs(["[ Playbook de Decisões ]", "[ Memória Comportamental ]", "[ Atuação na Borda ]", "[ Auditoria da IA ]"])

with tab1:
    st.subheader("Histórico Global de Decisões")
    if not df_playbook.empty:
        filtros = st.multiselect("Filtrar por Veredito:", options=df_playbook['veredito'].unique(), default=df_playbook['veredito'].unique())
        df_filtrado = df_playbook[df_playbook['veredito'].isin(filtros)]
        
        def cor_veredito(val):
            if val == 'BLOQUEAR': return 'color: #ff4b4b; font-weight: bold;'
            if val == 'MONITORAR': return 'color: #ffa421; font-weight: bold;'
            if val == 'FALSO_POSITIVO': return 'color: #00c04b; font-weight: bold;'
            return ''
            
        # Reorganiza as colunas para dar destaque à confiança e auto-correção
        colunas_exibicao = ['id_alvo', 'veredito', 'nivel_confianca', 'auto_corrigido', 'dica_rag', 'padrao_ataque', 'justificativa']
        colunas_reais = [c for c in colunas_exibicao if c in df_filtrado.columns]
        
        st.dataframe(df_filtrado[colunas_reais].style.map(cor_veredito, subset=['veredito']), use_container_width=True, hide_index=True)
    else:
        st.info("Nenhuma decisão registrada no momento.")

with tab2:
    st.subheader("Topologia do Grafo (Dependências Espaciais e Temporais)")
    if dados_memoria:
        lista = []
        for ip, info in dados_memoria.items():
            alvos = info.get("quantidade_alvos", 0)
            eventos = info.get("total_eventos_acumulados", 0)
            
            # Nova lógica de status baseada em Espaço e Tempo
            if alvos > 3: status = "Dispersão Espacial (Anomalia)"
            elif eventos > 100: status = "Volume Temporal (Burst)"
            else: status = "Tráfego Padrão (99%)"
                
            lista.append({"Nó (IP)": ip, "Status": status, "Total de Arestas (Volume)": eventos, "Alvos Conectados (Espaço)": alvos})
            
        st.dataframe(pd.DataFrame(lista).sort_values(by="Total de Arestas (Volume)", ascending=False), use_container_width=True, hide_index=True)
    else:
        st.info("Memória do Grafo vazia.")

with tab3:
    c_fw1, c_fw2 = st.columns(2)
    with c_fw1:
        st.error("Lista Negra - Firewall (Early-Drop)")
        if linhas_blacklist:
            for linha in reversed(linhas_blacklist[-15:]): st.code(linha.strip(), language="bash")
        else:
            st.info("Nenhum IP na Blacklist no momento.")
    with c_fw2:
        st.warning("Lista de Observação - SIEM")
        if linhas_watchlist:
            for linha in reversed(linhas_watchlist[-15:]): st.code(linha.strip(), language="bash")
        else:
            st.info("Nenhum IP em monitoramento no momento.")

with tab4:
    st.subheader("Auditoria de Desempenho (Juiz 70B)")
    
    # --- GRÁFICO DE ALUCINAÇÃO (CONFIANÇA VS ACURÁCIA) ---
    if dados_juiz and not df_playbook.empty and 'nivel_confianca' in df_playbook.columns:
        df_aud = pd.DataFrame(dados_juiz).rename(columns={"ip": "id_alvo"})
        df_aud = df_aud.drop_duplicates(subset=['id_alvo'], keep='last')
        df_cruzado = pd.merge(df_playbook, df_aud, on="id_alvo", how="inner")
        
        if not df_cruzado.empty:
            df_cruzado['nivel_confianca'] = pd.Categorical(df_cruzado['nivel_confianca'], categories=['BAIXA', 'MEDIA', 'ALTA'], ordered=True)
            fig = px.box(df_cruzado, x='nivel_confianca', y='acuracia_decisao', color='nivel_confianca',
                         title="Quantificação de Incerteza vs. Acurácia do Juiz",
                         labels={'nivel_confianca': 'Nível de Confiança do SLM', 'acuracia_decisao': 'Nota de Acurácia (0-10)'},
                         points="all", color_discrete_map={'BAIXA': '#ff4b4b', 'MEDIA': '#ffa421', 'ALTA': '#00c04b'})
            fig.update_yaxes(range=[0, 11])
            st.plotly_chart(fig, use_container_width=True)

    # --- LISTA DE AUDITORIAS ---
    if dados_juiz:
        for av in reversed(dados_juiz):
            ip = av.get("ip", "Desconhecido")
            decisao = av.get("decisao", "N/A")
            st.markdown(f"**Nó Auditado:** {ip} | **Veredito do Analista:** {decisao}")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Fidelidade Factual", f"{av.get('fidelidade_factual', 0)}/10")
            c2.metric("Acurácia da Decisão", f"{av.get('acuracia_decisao', 0)}/10")
            c3.metric("Raciocínio Lógico", f"{av.get('qualidade_raciocinio', 0)}/10")
            c4.metric("Adesão à Instrução", f"{av.get('adesao_instrucao', 0)}/10")
            st.info(f"**Parecer do Auditor:** {av.get('parecer_juiz', '')}")
            st.divider()
    else:
        st.info("Nenhuma avaliação encontrada. Rode o Juiz (Opção 3) para gerar as métricas.")