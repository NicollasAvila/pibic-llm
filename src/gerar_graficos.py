import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import os

# --- CONFIGURAÇÃO ---
# Garante que acha o arquivo CSV independente de onde roda
base_dir = os.path.dirname(os.path.abspath(__file__))
caminho_csv = os.path.join(base_dir, "..", "resultados", "relatorio_cientifico_final.csv")
pasta_saida = os.path.join(base_dir, "..", "resultados")

# Estilo visual "Acadêmico" (Limpo e profissional)
plt.style.use('bmh') 
sns.set_context("paper", font_scale=1.2)

def main():
    # 1. Carregar Dados
    try:
        df = pd.read_csv(caminho_csv)
        print(f"✅ Dados carregados: {len(df)} registros.")
    except Exception as e:
        print(f"❌ Erro ao ler CSV: {e}")
        return

    # --- GRÁFICO 1: DESEMPENHO POR CENÁRIO (Barras) ---
    plt.figure(figsize=(10, 6))
    
    # Agrupa por cenário e calcula a média das notas
    media_por_cenario = df.groupby('Cenario_Teste')['Nota_Juiz'].mean().reset_index()
    
    # Cria o gráfico de barras
    bar_plot = sns.barplot(
        x='Cenario_Teste', 
        y='Nota_Juiz', 
        data=media_por_cenario, 
        palette="viridis",
        hue='Cenario_Teste',
        legend=False
    )
    
    # Ajustes visuais
    plt.title('Performance Média do Agente por Tipo de Cenário', pad=20, fontsize=14, fontweight='bold')
    plt.ylabel('Nota Média (0-10)')
    plt.xlabel('Cenário de Teste')
    plt.ylim(0, 10.5) # Garante que vai até 10
    
    # Adiciona os valores em cima das barras
    for p in bar_plot.patches:
        bar_plot.annotate(f'{p.get_height():.2f}', 
                          (p.get_x() + p.get_width() / 2., p.get_height()), 
                          ha = 'center', va = 'center', 
                          xytext = (0, 9), 
                          textcoords = 'offset points',
                          fontweight='bold')

    # Salva
    caminho_img1 = os.path.join(pasta_saida, "fig2_desempenho_cenarios.png")
    plt.tight_layout()
    plt.savefig(caminho_img1, dpi=300) # dpi=300 é alta resolução para impressão
    print(f"📊 Gráfico 1 salvo em: {caminho_img1}")

    # --- GRÁFICO 2: ADESÃO AO CONTEXTO (Pizza) ---
    plt.figure(figsize=(8, 8))
    
    # Conta quantos True/False
    contagem = df['Seguiu_Contexto'].value_counts()
    
    # Se só tiver True (100%), o gráfico de pizza pode ficar estranho, então tratamos:
    labels = [f"Sim ({v})" if k else f"Não ({v})" for k, v in contagem.items()]
    colors = ['#4CAF50', '#F44336'] # Verde para Sim, Vermelho para Não
    
    plt.pie(contagem, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors, 
            textprops={'fontsize': 14, 'weight': 'bold'})
    
    plt.title('Taxa de Adesão ao Protocolo MCP\n(O Agente respeitou a Intel Externa?)', fontsize=14, fontweight='bold')
    
    # Salva
    caminho_img2 = os.path.join(pasta_saida, "fig3_adesao_contexto.png")
    plt.tight_layout()
    plt.savefig(caminho_img2, dpi=300)
    print(f"🍕 Gráfico 2 salvo em: {caminho_img2}")

if __name__ == "__main__":
    main()