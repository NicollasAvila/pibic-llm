import streamlit as st
import json
import os
import pandas as pd

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

# --- KPIs ---
col1, col2, col3, col4 = st.columns(4)
col1.metric("Perfis Mapeados (UBA)", len(dados_memoria) if dados_memoria else 0)
col2.metric("Ameaças Bloqueadas (DROP)", len(linhas_blacklist))
col3.metric("Acessos Suspeitos (MONITOR)", len(linhas_watchlist))
col4.metric("Motor de Inferência Ativo", "Llama 3.1 8B")
st.markdown("<br>", unsafe_allow_html=True)

# --- ABAS ---
tab1, tab2, tab3, tab4 = st.tabs(["[ Playbook de Decisões ]", "[ Memória Comportamental ]", "[ Atuação na Borda ]", "[ Auditoria da IA ]"])

with tab1:
    st.subheader("Histórico Global de Decisões")
    if dados_playbook:
        df_playbook = pd.DataFrame(dados_playbook)
        filtros = st.multiselect("Filtrar por Veredito:", options=df_playbook['veredito'].unique(), default=df_playbook['veredito'].unique())
        df_filtrado = df_playbook[df_playbook['veredito'].isin(filtros)]
        
        def cor_veredito(val):
            if val == 'BLOQUEAR': return 'color: #ff4b4b; font-weight: bold;'
            if val == 'MONITORAR': return 'color: #ffa421; font-weight: bold;'
            if val == 'FALSO_POSITIVO': return 'color: #00c04b; font-weight: bold;'
            return ''
            
        st.dataframe(df_filtrado.style.map(cor_veredito, subset=['veredito']), use_container_width=True, hide_index=True)
    else:
        st.info("Nenhuma decisão registrada. Execute o Orquestrador.")

with tab2:
    st.subheader("Grafo de Confiança (UBA)")
    if dados_memoria:
        lista = []
        for ip, info in dados_memoria.items():
            qtd_conf = len(info.get("conexoes_sucesso", {}))
            status = "Confiável" if qtd_conf >= 5 else ("Misto" if qtd_conf > 0 else "Desconhecido")
            lista.append({"IP": ip, "Status": status, "Total Acessos": info.get("total_eventos_acumulados", 0), "Alvos": info.get("quantidade_alvos", 0)})
        st.dataframe(pd.DataFrame(lista).sort_values(by="Total Acessos", ascending=False), use_container_width=True, hide_index=True)
    else:
        st.info("Memória vazia.")

with tab3:
    c_fw1, c_fw2 = st.columns(2)
    with c_fw1:
        st.error("Lista Negra - Firewall")
        for linha in reversed(linhas_blacklist[-15:]): st.code(linha.strip(), language="bash")
    with c_fw2:
        st.warning("Lista de Observação - SIEM")
        for linha in reversed(linhas_watchlist[-15:]): st.code(linha.strip(), language="bash")

with tab4:
    st.subheader("Auditoria de Desempenho (Juiz 70B)")
    if dados_juiz:
        for av in reversed(dados_juiz):
            ip = av.get("ip", "Desconhecido")
            decisao = av.get("decisao", "N/A")
            st.markdown(f"**IP:** {ip} | **Decisão:** {decisao}")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Fidelidade Factual", f"{av.get('fidelidade_factual', 0)}/10")
            c2.metric("Acurácia", f"{av.get('acuracia_decisao', 0)}/10")
            c3.metric("Raciocínio", f"{av.get('qualidade_raciocinio', 0)}/10")
            c4.metric("Instrução", f"{av.get('adesao_instrucao', 0)}/10")
            st.info(f"**Parecer:** {av.get('parecer_juiz', '')}")
            st.divider()
    else:
        st.info("Nenhuma avaliação encontrada. Rode o Juiz (Opção 3).")