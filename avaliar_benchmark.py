import json
import os
import time
from src.core.camada_avaliacao import JuizSTReasoner

# Importe a função principal do seu pipeline
# from src.main_pipeline import processar_lote

def carregar_gabarito():
    """Carrega o arquivo gerado pelo script de Red Team com a verdade absoluta."""
    caminho = "dados/raw/gabarito_ataques.json"
    if not os.path.exists(caminho):
        # Mock para o exemplo rodar
        return {"192.168.1.100": "Força Bruta SSH", "10.0.0.5": "Varredura Ransomware SMB"}
    with open(caminho, "r") as f:
        return json.load(f)

def rodar_experimento_pibic():
    print("🚀 Iniciando Benchmark do Llama-Cyber (ST-Bench Adaptation)...")
    
    juiz = JuizSTReasoner()
    gabarito = carregar_gabarito()
    resultados_benchmark = []
    
    # Simulação da extração de um lote que passou pelas Camadas 1, 2 e 3
    # Na prática, você iteraria sobre a saída real do seu main_pipeline.py
    lotes_testes = [
        {
            "ip": "192.168.1.100",
            "contexto_c1_c2": "[TENDÊNCIA: BURST] 500 falhas SSH em 2s. [DICA RAG] Nenhuma ameaça conhecida no FAISS.",
            "resposta_agente": '{"veredicto": "BLOQUEAR", "justificativa": "Ataque de força bruta intenso em pouco tempo, configurando anomalia no grafo."}'
        }
    ]

    for teste in lotes_testes:
        print(f"\nAvaliando processamento do IP {teste['ip']}...")
        ataque_real = gabarito.get(teste["ip"], "Tráfego Benigno")
        
        avaliacao = juiz.avaliar(
            contexto_completo=teste["contexto_c1_c2"],
            resposta_agente=teste["resposta_agente"],
            gabarito_real=ataque_real
        )
        
        if avaliacao:
            resultados_benchmark.append({
                "ip": teste["ip"],
                "nota": avaliacao.nota_final,
                "metricas": avaliacao.metricas.dict(),
                "analise": avaliacao.justificativa
            })
            print(f"✅ Nota Final: {avaliacao.nota_final}/5.0")
            print(f"💡 Justificativa: {avaliacao.justificativa}")
        
        time.sleep(1) # Respeitar rate limit da API

    # Exportar resultados para gráficos do artigo
    os.makedirs("resultados", exist_ok=True)
    with open("resultados/metricas_avaliacao.json", "w") as f:
        json.dump(resultados_benchmark, f, indent=4)
    print("\n📊 Relatório de benchmark salvo em 'resultados/metricas_avaliacao.json'.")

if __name__ == "__main__":
    rodar_experimento_pibic()