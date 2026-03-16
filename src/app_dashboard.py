import streamlit as st
import json
import os
import pandas as pd
import plotly.express as px

# 1. Configuração da Página
st.set_page_config(page_title="SOC AI - Sentinel", layout="wide", page_icon="🛡️")

# 2. Funções de Leitura
@st.cache_data
def carregar_json(caminho):
    if os.path.exists(caminho):
        with open(caminho, "r", encoding="utf-8") as f:
            return json.load(f)
    return None

def ler_linhas_arquivo(caminho):
    if os.path.exists(caminho):
        with open(caminho, "r", encoding="utf-8") as f:
            return f.readlines()
    return []

# Carregando Dados
dados_playbook = carregar_json("../resultados/playbook_lote_1.json")
dados_memoria = carregar_json("../resultados/memoria_global_ips.json")
linhas_blacklist = ler_linhas_arquivo("../resultados/blacklist_firewall.txt")
linhas_watchlist = ler_linhas_arquivo("../resultados/watchlist_siem.txt")
dados_auditoria = carregar_json("../resultados/auditoria_lote_1.json")

# 3. Cabeçalho
st.title("🛡️ Centro de Operações de Segurança (SOC) Autônomo")
st.markdown("Monitoramento de IA Espaço-Temporal e Auditoria LLM-as-a-Judge")
st.divider()

# 4. Navegação Principal (O Segredo da Intuição)
tab_geral, tab_auditoria, tab_firewall = st.tabs([
    "📊 Visão Geral e Ameaças", 
    "⚖️ Auditoria de IA (Juiz 70B)", 
    "🧱 Ações Físicas (Firewall/SIEM)"
])

# ==========================================
# ABA 1: VISÃO GERAL
# ==========================================
with tab_geral:
    st.subheader("Métricas em Tempo Real")
    col1, col2, col3, col4 = st.columns(4)
    
    col1.metric("Ameaças Mapeadas", len(dados_memoria) if dados_memoria else 0)
    col2.metric("Ataques Críticos (DROP)", len(linhas_blacklist), delta="Bloqueados", delta_color="inverse")
    col3.metric("Tráfego Suspeito (MONITOR)", len(linhas_watchlist), delta="Em observação", delta_color="off")
    col4.metric("Piloto Atual (SLM)", "Llama 3.1 8B")

    st.markdown("<br>", unsafe_allow_html=True)
    
    col_esq, col_dir = st.columns([1, 1])
    
    with col_esq:
        st.markdown("#### 🧠 Últimas Decisões do Agente (Playbook)")
        if dados_playbook and "incidentes" in dados_playbook:
            df_playbook = pd.DataFrame(dados_playbook["incidentes"])
            def colorir_veredito(val):
                cor = '#ff4b4b' if val == 'BLOQUEAR' else '#ffa421' if val == 'MONITORAR' else '#00c04b'
                return f'color: {cor}; font-weight: bold;'
            st.dataframe(df_playbook.style.map(colorir_veredito, subset=['veredito']), use_container_width=True, hide_index=True)
        else:
            st.info("Nenhuma decisão recente.")

    with col_dir:
        st.markdown("#### 🌍 Top IPs Ofensores (Memória Global)")
        if dados_memoria:
            memoria_lista = [{"IP": ip, "Acessos": info.get("total_eventos_acumulados", 0)} for ip, info in dados_memoria.items()]
            df_grafico = pd.DataFrame(memoria_lista).sort_values(by="Acessos", ascending=False).head(5)
            
            # Gráfico de Barras Elegante
            fig = px.bar(df_grafico, x="Acessos", y="IP", orientation='h', 
                         color="Acessos", color_continuous_scale="Reds",
                         title="Volume de Ataques por IP (Histórico)")
            fig.update_layout(yaxis={'categoryorder':'total ascending'}, margin=dict(l=0, r=0, t=30, b=0))
            st.plotly_chart(fig, use_container_width=True)

# ==========================================
# ABA 2: AUDITORIA (LLM-as-a-Judge)
# ==========================================
with tab_auditoria:
    st.subheader("Tribunal de Avaliação Contínua")
    st.markdown("O modelo **Llama 3.3 70B** audita as decisões do nosso SLM baseando-se no contexto real dos logs.")
    
    if dados_auditoria:
        for aud in dados_auditoria:
            with st.expander(f"📌 Avaliação do IP: {aud.get('ip_avaliado')} | Decisão do SLM: {aud.get('veredito_slm')}", expanded=True):
                notas = aud.get("notas", {})
                
                c1, c2, c3, c4 = st.columns(4)
                c1.metric("Fidelidade Factual", f"{notas.get('fidelidade_factual', 0)}/10")
                c2.metric("Acurácia da Decisão", f"{notas.get('acuracia_decisao', 0)}/10")
                c3.metric("Qualidade do Raciocínio", f"{notas.get('qualidade_raciocinio', 0)}/10")
                c4.metric("Adesão à Instrução", f"{notas.get('adesao_instrucao', 0)}/10")
                
                st.info(f"**Parecer do Juiz:** {notas.get('comentario_auditoria', '')}")
    else:
        st.warning("Nenhuma auditoria realizada ainda.")

# ==========================================
# ABA 3: AÇÕES FÍSICAS (MCP)
# ==========================================
with tab_firewall:
    st.subheader("Atuação Agêntica na Infraestrutura")
    col_b, col_w = st.columns(2)
    
    with col_b:
        st.error("🔥 Blacklist do Firewall (Regras DROP)")
        st.markdown("IPs injetados autonomamente para bloqueio imediato:")
        if linhas_blacklist:
            codigo_bash = "".join(linhas_blacklist)
            st.code(codigo_bash, language="bash")
        else:
            st.write("Sem bloqueios.")

    with col_w:
        st.warning("👀 Watchlist do SIEM (Regras MONITOR)")
        st.markdown("IPs injetados para monitoramento contínuo de segurança:")
        if linhas_watchlist:
            codigo_bash = "".join(linhas_watchlist)
            st.code(codigo_bash, language="bash")
        else:
            st.write("Sem monitoramentos.")