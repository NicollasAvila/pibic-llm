import random
import re
import logging
from datetime import datetime, timedelta

logger = logging.getLogger("RedTeam_Em_Memoria")

ARSENAL_ATAQUES = [
    {"id": "T1110.001", "nome": "Força Bruta SSH", "porta": "22", "acao": "DROP", "total_eventos": 50, "duracao_segundos": 2},
    {"id": "T1021.002", "nome": "Varredura SMB", "porta": "445", "acao": "DROP", "total_eventos": 25, "duracao_segundos": 10},
    {"id": "T1046", "nome": "Port Scan", "portas": ["22", "80", "443", "3389", "8080"], "acao": "DENY", "total_eventos": 15, "duracao_segundos": 5},
    {"id": "T1190", "nome": "Exploração Web (Burst)", "porta": "80", "acao": "DROP", "total_eventos": 80, "duracao_segundos": 3}
]

def extrair_tempo(linha):
    match = re.search(r'generated_time="([^"]+)"', linha)
    if match:
        try:
            return datetime.strptime(match.group(1), "%Y/%m/%d %H:%M:%S")
        except:
            return None
    return None

def injetar_ataque_no_lote(linhas_reais, probabilidade_injecao=1.0):
    """Intercepta um lote de logs na RAM e decide se injeta um ataque."""
    if random.random() > probabilidade_injecao or len(linhas_reais) < 10:
        return linhas_reais

    tempos = [extrair_tempo(l) for l in linhas_reais]
    tempos_validos = [t for t in tempos if t is not None]
    
    if not tempos_validos:
        return linhas_reais
        
    time_start = min(tempos_validos)
    time_end = max(tempos_validos)
    
    if time_start == time_end:
        time_end += timedelta(seconds=10)

    src_ips = list(set(re.findall(r'src_ip=([^\s]+)', "".join(linhas_reais))))
    dst_ips = list(set(re.findall(r'dst_ip=([^\s]+)', "".join(linhas_reais))))
    
    attacker_ip = random.choice(src_ips) if src_ips else "185.12.33.9"
    target_ip = random.choice(dst_ips) if dst_ips else "10.0.0.8"

    ataque = random.choice(ARSENAL_ATAQUES)
    logger.info(f"🔥 INJEÇÃO EM MEMÓRIA: {ataque['nome']} usando IP Zumbi: {attacker_ip}")

    segundos_disponiveis = max(1, int((time_end - time_start).total_seconds()))
    start_ataque = time_start + timedelta(seconds=random.randint(0, max(0, segundos_disponiveis - ataque['duracao_segundos'])))

    linhas_sinteticas = []
    for i in range(ataque['total_eventos']):
        tempo_evento = start_ataque + timedelta(milliseconds=random.randint(0, ataque['duracao_segundos']*1000))
        porta = random.choice(ataque['portas']) if 'portas' in ataque else ataque['porta']
        
        nova_linha = (
            f'generated_time="{tempo_evento.strftime("%Y/%m/%d %H:%M:%S")}" '
            f'src_ip={attacker_ip} dst_ip={target_ip} dst_port={porta} action={ataque["acao"]} '
            f'proto=tcp notes="Emulacao_RAM: {ataque["nome"]}"\n'
        )
        linhas_sinteticas.append(nova_linha)

    lote_misto = linhas_reais + linhas_sinteticas
    
    def get_sort_key(linha):
        t = extrair_tempo(linha)
        return t if t else datetime.min
        
    lote_misto.sort(key=get_sort_key)
    
    return lote_misto