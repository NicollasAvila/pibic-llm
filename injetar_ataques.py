import os

# Definimos o caminho diretamente para evitar o erro de importação
DADOS_RAW_DIR = "dados/raw"

def gerar_ataques_sinteticos():
    linhas_ataque = []
    
    # 1. Ataque de Força Bruta SSH (Alta Frequência - Tempo)
    # 50 tentativas de login no mesmo segundo de um IP suspeito
    ip_brute_force = "188.166.25.14" # IP fictício de atacante
    for i in range(50):
        linha = f'2026 Jan 20 00:00:00 poc-coleta-log->127.0.0.1 PaloAlto: generated_time="2026/01/19 21:00:00" src_ip={ip_brute_force} dst_ip=10.1.1.50 dst_port=22 action=deny\n'
        linhas_ataque.append(linha)
        
    # 2. Varredura de Rede SMB / Ransomware (Múltiplos Alvos - Espaço)
    # O atacante tenta espalhar-se por 15 máquinas diferentes na porta 445
    ip_scanner = "103.145.12.99" # IP fictício de atacante
    for i in range(1, 16):
        linha = f'2026 Jan 20 00:00:01 poc-coleta-log->127.0.0.1 PaloAlto: generated_time="2026/01/19 21:00:01" src_ip={ip_scanner} dst_ip=10.1.1.{i} dst_port=445 action=deny\n'
        linhas_ataque.append(linha)

    return linhas_ataque

def injetar_nos_logs_reais():
    caminho_original = os.path.join(DADOS_RAW_DIR, "ossec-archive-13.log")
    caminho_novo = os.path.join(DADOS_RAW_DIR, "ossec-archive-demo.log")
    
    print("Gerando ataques sintéticos (Red Team)...")
    ataques = gerar_ataques_sinteticos()
    
    print(f"Lendo log real: {caminho_original}")
    # Lê as primeiras 4900 linhas do log real (para caber no nosso bloco de 5000)
    linhas_reais = []
    try:
        with open(caminho_original, "r", encoding="utf-8") as f:
            for _ in range(4900):
                linha = f.readline()
                if not linha:
                    break
                linhas_reais.append(linha)
    except FileNotFoundError:
        print(f"Arquivo original não encontrado na pasta {DADOS_RAW_DIR}. Verifique se o nome está correto.")
        return

    print("Misturando ataques com tráfego real...")
    # Coloca os ataques no topo, seguidos do tráfego normal
    conteudo_final = ataques + linhas_reais

    with open(caminho_novo, "w", encoding="utf-8") as f:
        f.writelines(conteudo_final)
        
    print(f"✅ Sucesso! Novo arquivo de demonstração criado em: {caminho_novo}")
    print(f"Total de linhas prontas para a IA: {len(conteudo_final)}")

if __name__ == "__main__":
    injetar_nos_logs_reais()