import random
import re
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("RedTeam_Em_Memoria")

# =====================================================================
# 🚀 OTIMIZAÇÃO: REGEX PRÉ-COMPILADO (Elimina o gargalo do CPU)
# =====================================================================
RE_TIME = re.compile(r'generated_time="([^"]+)"')
RE_SRC  = re.compile(r'src_ip=([^\s]+)')
RE_DST  = re.compile(r'dst_ip=([^\s]+)')

ARSENAL_ATAQUES = [
    {"id": "T1110.001", "nome": "Força Bruta SSH", "porta": "22", "acao": "DROP", "total_eventos": 50, "duracao_segundos": 2, "app": "ssh"},
    {"id": "T1021.002", "nome": "Varredura SMB", "porta": "445", "acao": "DROP", "total_eventos": 25, "duracao_segundos": 10, "app": "smb"},
    {"id": "T1046", "nome": "Port Scan", "portas": ["22", "80", "443", "3389", "8080"], "acao": "DENY", "total_eventos": 15, "duracao_segundos": 5, "app": "unknown"},
    {"id": "T1190", "nome": "Exploração Web (Burst)", "porta": "80", "acao": "DROP", "total_eventos": 80, "duracao_segundos": 3, "app": "web-browsing"}
]

def extrair_tempo_str(linha):
    """Retorna a string pura da data. É 100x mais rápido para ordenação do que usar datetime."""
    match = RE_TIME.search(linha)
    return match.group(1) if match else "0000/00/00 00:00:00"

def injetar_ataque_no_lote(linhas_reais, probabilidade_injecao=1.0):
    """Intercepta um lote de logs na RAM e decide se injeta um ataque à velocidade da luz."""
    if random.random() > probabilidade_injecao or len(linhas_reais) < 10:
        return linhas_reais

    # Extrai limites de tempo usando apenas strings (Muito rápido)
    tempos_str = [extrair_tempo_str(l) for l in linhas_reais]
    tempos_validos = [t for t in tempos_str if t != "0000/00/00 00:00:00"]
    
    if not tempos_validos:
        return linhas_reais
        
    time_start = datetime.strptime(min(tempos_validos), "%Y/%m/%d %H:%M:%S")
    time_end = datetime.strptime(max(tempos_validos), "%Y/%m/%d %H:%M:%S")
    
    if time_start == time_end:
        time_end += timedelta(seconds=10)

    # 🚀 OTIMIZAÇÃO: Em vez de varrer 4500 linhas, inspeciona apenas 30 linhas aleatórias para roubar um IP real
    amostra = random.sample(linhas_reais, min(30, len(linhas_reais)))
    src_ips = []
    dst_ips = []
    for l in amostra:
        m_src = RE_SRC.search(l)
        m_dst = RE_DST.search(l)
        if m_src: src_ips.append(m_src.group(1))
        if m_dst: dst_ips.append(m_dst.group(1))

    attacker_ip = random.choice(src_ips) if src_ips else "185.12.33.9"
    target_ip = random.choice(dst_ips) if dst_ips else "10.0.0.8"

    ataque = random.choice(ARSENAL_ATAQUES)
    logger.info(f"🔥 [RED TEAM] Injetando: {ataque['nome']} mascarado no IP: {attacker_ip}")

    segundos_disponiveis = max(1, int((time_end - time_start).total_seconds()))
    start_ataque = time_start + timedelta(seconds=random.randint(0, max(0, segundos_disponiveis - ataque['duracao_segundos'])))

    linhas_sinteticas = []
    for i in range(ataque['total_eventos']):
        tempo_evento = start_ataque + timedelta(milliseconds=random.randint(0, ataque['duracao_segundos']*1000))
        porta = random.choice(ataque['portas']) if 'portas' in ataque else ataque['porta']
        
        # 🛡️ COMPATIBILIDADE: Adicionado 'rule_name' e 'application' para a Camada 1 conseguir validar
        nova_linha = (
            f'generated_time="{tempo_evento.strftime("%Y/%m/%d %H:%M:%S")}" '
            f'src_ip={attacker_ip} dst_ip={target_ip} dst_port={porta} action={ataque["acao"]} '
            f'rule_name=Alerta_RedTeam application={ataque["app"]} proto=tcp notes="Emulacao_RAM"\n'
        )
        linhas_sinteticas.append(nova_linha)

    # Junta o lote e ordena usando a string do tempo (Ordem Lexicográfica é nativa e veloz no Python)
    lote_misto = linhas_reais + linhas_sinteticas
    lote_misto.sort(key=extrair_tempo_str)
    
    return lote_misto