import matplotlib.pyplot as plt
import numpy as np

# Set style
plt.style.use('seaborn-v0_8-whitegrid')
plt.rcParams.update({'font.size': 12, 'font.family': 'sans-serif'})

# Data for Quantitative (TPS)
models_tps = ['AegisV3', 'Llama 3.2 3B', 'Llama 3.1 8B', 'Qwen 2.5', 'Llama 70B (Cloud)']
tps_values = [103.81, 97.82, 72.37, 72.58, 67.16]
colors_tps = ['#2ca02c', '#1f77b4', '#1f77b4', '#1f77b4', '#ff7f0e']

fig, ax = plt.subplots(figsize=(8, 5))
bars = ax.bar(models_tps, tps_values, color=colors_tps)
ax.set_ylabel('Vazao (Tokens por Segundo)')
ax.set_title('Desempenho de Inferencia (TPS) por Modelo - Hardware: RTX 5060 8GB')
ax.set_ylim(0, 120)

for bar in bars:
    height = bar.get_height()
    ax.annotate(f'{height:.1f}',
                xy=(bar.get_x() + bar.get_width() / 2, height),
                xytext=(0, 3),  
                textcoords='offset points',
                ha='center', va='bottom', fontweight='bold')

plt.tight_layout()
plt.savefig(r'c:\Projetos\pibic-llm\artigo\tps_comparativo.png', dpi=300)
plt.close()

# Data for Qualitative
models_qual = ['Llama 3.2 3B\n(Base)', 'Llama 3.3 70B\n(Cloud API)', 'AegisV3\n(Especialista)']
acuracia = [5.56, 10.0, 10.0]
fidelidade = [7.22, 8.78, 10.0]
raciocinio = [6.78, 8.33, 9.0]

x = np.arange(len(models_qual))  # the label locations
width = 0.25  # the width of the bars

fig, ax = plt.subplots(figsize=(9, 5))
rects1 = ax.bar(x - width, acuracia, width, label='Acuracia da Decisao', color='#d62728')
rects2 = ax.bar(x, fidelidade, width, label='Fidelidade Factual', color='#1f77b4')
rects3 = ax.bar(x + width, raciocinio, width, label='Qualidade de Raciocinio', color='#2ca02c')

ax.set_ylabel('Pontuacao (0 - 10)')
ax.set_title('Avaliacao Sintetica (LLM-as-a-Judge) das Qualidades Analiticas')
ax.set_xticks(x)
ax.set_xticklabels(models_qual)
ax.legend(loc='upper center', ncol=3)
ax.set_ylim(0, 13)

def autolabel(rects):
    for rect in rects:
        height = rect.get_height()
        ax.annotate(f'{height:.2f}',
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 3), 
                    textcoords='offset points',
                    ha='center', va='bottom', fontsize=10)

autolabel(rects1)
autolabel(rects2)
autolabel(rects3)

plt.tight_layout()
plt.savefig(r'c:\Projetos\pibic-llm\artigo\qualidade_comparativa.png', dpi=300)
plt.close()
