import ollama
import json
import os

# CONFIGURAÇÕES
MODELO_CRIATIVO = "llama3.1"
ARQUIVO_SAIDA = "../dados/dataset_sintetico.json"

CENARIOS = [
    "Ransomware WannaCry detectado tentando criptografar arquivos",
    "Tentativa de Brute Force SSH vindo de IP externo",
    "SQL Injection em aplicação web bloqueado pelo WAF",
    "Exfiltração de dados (DLP) detectada via DNS Tunneling",
    "Criação de usuário Admin suspeito no Active Directory",
    "Minerador de Criptomoeda (Coinminer) detectado em servidor",
    "Spyware tentando conexão com Command & Control (C2)",
    "Port Scanning (Nmap) detectado na rede interna",
    "Tentativa de exploração Log4Shell (Log4j)",
    "Execução de Script PowerShell Malicioso (Encoded Command)"
]

# AQUI ESTÁ A MÁGICA: Passamos a estrutura do Wazuh como exemplo
PROMPT_GERADOR = """
Você é um simulador de logs de SIEM (Wazuh).
Sua tarefa é gerar UM objeto JSON seguindo ESTRITAMENTE a estrutura abaixo, mas adaptando os dados para o cenário: "{cenario}".

ESTRUTURA BASE (Mantenha as chaves iguais, mude apenas os valores):
{{
    "timestamp": "2025-12-10T16:04:49.801+0000",
    "rule": {{
        "level": 10,
        "description": "<DESCRIÇÃO DO ATAQUE AQUI>",
        "id": "100601",
        "firedtimes": 1,
        "groups": ["security_event", "attack"]
    }},
    "agent": {{ "id": "001", "name": "srv-prod-01" }},
    "manager": {{ "name": "wazuh-manager" }},
    "id": "1765382689.306221254",
    "data": {{
        "src_ip": "<INVENTE UM IP DE ORIGEM>",
        "dst_ip": "<INVENTE UM IP DE DESTINO>",
        "username": "<USUARIO>",
        "ThreatName": "<NOME TÉCNICO DA AMEAÇA>",
        "TargetProcessName": "<PROCESSO SUSPEITO EX: POWERSHELL.EXE>",
        "Action": "Blocked",
        "IoC_Artifact": "<INVENTE UM HASH OU URL MALICIOSA AQUI>"
    }}
}}

REGRAS:
1. O campo 'data' deve conter os detalhes técnicos do ataque.
2. O campo 'rule.description' deve resumir o ataque.
3. Responda APENAS o JSON. Sem markdown.
"""

def main():
    print(f"🏭 Iniciando Fábrica de Logs WAZUH ({len(CENARIOS)} cenários)...")
    logs_gerados = []

    for i, cenario in enumerate(CENARIOS):
        print(f"   [{i+1}/{len(CENARIOS)}] Gerando: {cenario}...")
        try:
            response = ollama.chat(model=MODELO_CRIATIVO, messages=[
                {'role': 'user', 'content': PROMPT_GERADOR.format(cenario=cenario)}
            ])
            
            texto = response['message']['content']
            texto = texto.replace("```json", "").replace("```", "").strip()
            
            dado = json.loads(texto)
            dado["_gabarito_ataque"] = cenario # Nosso gabarito oculto
            
            logs_gerados.append(dado)
            
        except Exception as e:
            print(f"   ❌ Erro ao gerar {i}: {e}")

    os.makedirs(os.path.dirname(ARQUIVO_SAIDA), exist_ok=True)
    with open(ARQUIVO_SAIDA, "w", encoding="utf-8") as f:
        json.dump(logs_gerados, f, indent=2, ensure_ascii=False)

    print(f"\n✅ {len(logs_gerados)} Logs estilo Wazuh salvos em: {ARQUIVO_SAIDA}")

if __name__ == "__main__":
    main()