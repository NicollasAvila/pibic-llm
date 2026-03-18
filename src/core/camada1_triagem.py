import os
import re
import json
import logging
import math
from datetime import datetime
from collections import defaultdict
from pydantic import BaseModel
from typing import List

logger = logging.getLogger("Camada1_ST_Triagem")

# --- NOVO: ESTRUTURAS DE DADOS PARA O ORQUESTRADOR (AGORA COM PYDANTIC) ---
# --- NOVO: ESTRUTURAS DE DADOS PARA O ORQUESTRADOR (AGORA COM PYDANTIC) ---
class Incidente(BaseModel):
    id_alvo: str
    padrao_ataque: str
    dica_rag: str = ""
    veredito: str = ""       # <-- Faltava isto! (Espaço para a IA escrever a decisão)
    justificativa: str = ""  # <-- Faltava isto! (Espaço para a IA escrever o motivo)

class RelatorioTriagem(BaseModel):
    incidentes: List[Incidente] = []

class PerfilAtacante:
    """Armazena o estado do grafo e do tempo para um IP de origem específico."""
    def __init__(self):
        self.primeiro_evento = None
        self.ultimo_evento = None
        self.alvos_dst = set()       
        self.portas_alvo = defaultdict(int) 
        self.acoes = defaultdict(int)       
        self.total_eventos = 0
        self.conexoes_sucesso = defaultdict(int)

    def to_dict(self):
        return {
            "primeiro_evento": self.primeiro_evento.strftime("%Y-%m-%d %H:%M:%S") if self.primeiro_evento else None,
            "ultimo_evento": self.ultimo_evento.strftime("%Y-%m-%d %H:%M:%S") if self.ultimo_evento else None,
            "quantidade_alvos": len(self.alvos_dst),
            "alvos_conhecidos": list(self.alvos_dst)[:10],
            "portas_alvo": dict(self.portas_alvo),
            "acoes_historicas": dict(self.acoes),
            "total_eventos_acumulados": self.total_eventos,
            "conexoes_sucesso": dict(list(self.conexoes_sucesso.items())[:10]) 
        }

class TriagemEspacoTemporal:
    """
    Camada 1: UBA e Extração Multimodal com MEMÓRIA, BASELINES E GRAFO DE CONFIANÇA.
    """
    def __init__(self):
        self.grafo_global = defaultdict(PerfilAtacante)

    def _calcular_baseline_estatistico(self):
        """Calcula a média e o desvio padrão da taxa de eventos da rede."""
        if not self.grafo_global:
            return 1.0, 0.0

        taxas = []
        for perfil in self.grafo_global.values():
            if perfil.primeiro_evento and perfil.ultimo_evento:
                delta_t = max(1.0, (perfil.ultimo_evento - perfil.primeiro_evento).total_seconds())
                taxas.append(perfil.total_eventos / delta_t)
            else:
                taxas.append(1.0)

        media = sum(taxas) / len(taxas)
        variancia = sum((x - media) ** 2 for x in taxas) / len(taxas)
        desvio_padrao = math.sqrt(variancia)

        return media, desvio_padrao

    def extrair_caracteres_st(self, lote_linhas: list) -> list:
        ips_ativos_neste_lote = set()
        
        for linha in lote_linhas:
            match_time = re.search(r'generated_time="([^"]+)"', linha)
            match_src = re.search(r'src_ip=([^\s]+)', linha)
            match_dst = re.search(r'dst_ip=([^\s]+)', linha)
            match_dpt = re.search(r'dst_port=(\d+)', linha)
            match_act = re.search(r'action=([a-zA-Z]+)', linha)
            
            if not (match_time and match_src and match_dst and match_dpt and match_act):
                continue
                
            tempo_str = match_time.group(1)
            src = match_src.group(1)
            dst = match_dst.group(1)
            dpt = match_dpt.group(1)
            acao = match_act.group(1).upper()
            
            try:
                tempo_obj = datetime.strptime(tempo_str, "%Y/%m/%d %H:%M:%S")
            except ValueError:
                continue
            
            ips_ativos_neste_lote.add(src)
            perfil = self.grafo_global[src]
            
            perfil.total_eventos += 1
            perfil.alvos_dst.add(dst)
            perfil.portas_alvo[dpt] += 1
            perfil.acoes[acao] += 1
            
            if acao == 'ALLOW':
                perfil.conexoes_sucesso[f"{dst}:{dpt}"] += 1
            
            if not perfil.primeiro_evento or tempo_obj < perfil.primeiro_evento:
                perfil.primeiro_evento = tempo_obj
            if not perfil.ultimo_evento or tempo_obj > perfil.ultimo_evento:
                perfil.ultimo_evento = tempo_obj

        self._salvar_memoria_disco()

        resumos_st_align = []
        media_rede, std_rede = self._calcular_baseline_estatistico()
        limiar_burst = max(2.0, media_rede + std_rede)

        for ip_src in ips_ativos_neste_lote:
            perfil = self.grafo_global[ip_src]
            
            conexoes_confiaveis = sum(1 for qtd in perfil.conexoes_sucesso.values() if qtd >= 5)
            media_eventos_global = sum(p.total_eventos for p in self.grafo_global.values()) / max(1, len(self.grafo_global))
            limiar_ruido = max(3, int(media_eventos_global * 0.05))

            if perfil.acoes.get('DENY', 0) == 0 and perfil.acoes.get('DROP', 0) == 0 and perfil.total_eventos < limiar_ruido:
                continue

            delta_t = (perfil.ultimo_evento - perfil.primeiro_evento).total_seconds()
            delta_t = max(1.0, delta_t) 
            
            taxa_por_segundo = perfil.total_eventos / delta_t
            
            if taxa_por_segundo > limiar_burst:
                char_temporal = f"[ANOMALIA ESTATÍSTICA: BURST] Taxa de {taxa_por_segundo:.1f} ev/s supera o baseline da rede ({media_rede:.1f} ev/s)."
            elif delta_t > 3600:
                char_temporal = f"[TENDÊNCIA: PERSISTÊNCIA] Atividade contínua observada ao longo de {int(delta_t/3600)} horas."
            else:
                char_temporal = f"[TENDÊNCIA: NORMAL] Atividade dentro do desvio padrão da rede."

            qtd_alvos = len(perfil.alvos_dst)
            alvos_str = ", ".join(list(perfil.alvos_dst)[:3])
            if qtd_alvos > 3: alvos_str += f" e mais {qtd_alvos - 3} nós"
            porta_principal = max(perfil.portas_alvo, key=perfil.portas_alvo.get)
            
            if qtd_alvos > 1:
                char_espacial = f"[MOVIMENTO DISTRIBUÍDO] IP {ip_src} conectou-se a {qtd_alvos} nós diferentes na rede."
            else:
                char_espacial = f"[FOCADO] IP {ip_src} tem alvo único no nó {alvos_str}."

            if conexoes_confiaveis > 0 and taxa_por_segundo < limiar_burst:
                char_confianca = f"[WHITELIST DINÂMICA: CONFIÁVEL] IP possui histórico consolidado de tráfego benigno com {conexoes_confiaveis} serviços."
            elif conexoes_confiaveis > 0:
                char_confianca = f"[GRAFO MISTO] IP possui conexões confiáveis, mas apresenta anomalias atuais."
            else:
                char_confianca = f"[DESCONHECIDO] Sem histórico de confiança estabelecido."

            resumo_final = (
                f"ST-ALIGN EVENTO | ORIGEM: {ip_src} | "
                f"COMPORTAMENTO: {char_confianca} | "
                f"ESPAÇO: {char_espacial} | "
                f"TEMPO: {char_temporal} | "
                f"INFLUÊNCIA: Foco principal na porta {porta_principal} com {perfil.acoes.get('DENY', 0)} bloqueios acumulados."
            )
            
            resumos_st_align.append(resumo_final)
            
        return resumos_st_align

    def processar_bloco(self, lote_linhas: list) -> RelatorioTriagem:
        resumos = self.extrair_caracteres_st(lote_linhas)
        # O Pydantic permite criar o objeto passando os incidentes como lista vazia inicialmente
        incidentes_lista = []
        
        for resumo in resumos:
            match_ip = re.search(r"ORIGEM:\s*([^\s|]+)", resumo)
            ip_alvo = match_ip.group(1) if match_ip else "Desconhecido"
            
            # Cria o modelo Pydantic do Incidente
            inc = Incidente(id_alvo=ip_alvo, padrao_ataque=resumo, dica_rag="")
            incidentes_lista.append(inc)
            
        return RelatorioTriagem(incidentes=incidentes_lista)

    def _salvar_memoria_disco(self):
        os.makedirs("resultados", exist_ok=True)
        caminho_memoria = "resultados/memoria_global_ips.json"
        dados_para_salvar = {ip: perfil.to_dict() for ip, perfil in self.grafo_global.items()}
        with open(caminho_memoria, "w", encoding="utf-8") as f:
            json.dump(dados_para_salvar, f, indent=4, ensure_ascii=False)