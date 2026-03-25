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

class Incidente(BaseModel):
    id_alvo: str
    padrao_ataque: str
    dica_rag: str = ""
    veredito: str = ""       
    justificativa: str = ""
    nivel_confianca: str = ""  # Preparação para a Camada 3

class RelatorioTriagem(BaseModel):
    incidentes: List[Incidente] = []

class PerfilAtacante:
    """O 'Nó' no nosso Grafo Espaço-Temporal."""
    def __init__(self):
        self.primeiro_evento = None
        self.ultimo_evento = None
        self.alvos_dst = set()       # Dependência Espacial (Arestas)
        self.portas_alvo = defaultdict(int) 
        self.total_eventos = 0       # Dinâmica Temporal (Volume)

    def to_dict(self):
        return {
            "primeiro_evento": self.primeiro_evento.strftime("%Y-%m-%d %H:%M:%S") if self.primeiro_evento else None,
            "ultimo_evento": self.ultimo_evento.strftime("%Y-%m-%d %H:%M:%S") if self.ultimo_evento else None,
            "quantidade_alvos": len(self.alvos_dst),
            "total_eventos_acumulados": self.total_eventos
        }

class TriagemEspacoTemporal:
    def __init__(self):
        self.grafo_global = defaultdict(PerfilAtacante)

    def _calcular_baseline_estatistico(self):
        if not self.grafo_global: return 1.0, 0.0
        taxas = []
        for perfil in self.grafo_global.values():
            if perfil.primeiro_evento and perfil.ultimo_evento:
                delta_t = max(1.0, (perfil.ultimo_evento - perfil.primeiro_evento).total_seconds())
                taxas.append(perfil.total_eventos / delta_t)
            else: taxas.append(1.0)
        media = sum(taxas) / len(taxas)
        variancia = sum((x - media) ** 2 for x in taxas) / len(taxas)
        return media, math.sqrt(variancia)

    def extrair_caracteres_st(self, lote_linhas: list) -> list:
        """
        Extrai características Espaço-Temporais e Contextuais (Palo Alto) dos logs.
        Implementa o alinhamento de contexto inspirado no módulo ST-Align do STReasoner.
        """
        ips_ativos_neste_lote = set()
        
        # Dicionários temporários para metadados de contexto do lote atual
        locais_ip = {}
        apps_ip = defaultdict(set)
        regras_ip = defaultdict(set)
        
        # 1. PARSING E ATUALIZAÇÃO DO GRAFO EM MEMÓRIA
        for linha in lote_linhas:
            # Regex robusto para Palo Alto (aceita aspas e caracteres especiais)
            match_time = re.search(r'generated_time="([^"]+)"', linha)
            match_src = re.search(r'src_ip=([^\s]+)', linha)
            match_dst = re.search(r'dst_ip=([^\s]+)', linha)
            match_dpt = re.search(r'dst_port=(\d+)', linha)
            # Aceita 'allow', 'drop', 'deny', 'reset-both', 'reset-server', etc.
            match_act = re.search(r'action=([a-zA-Z\-]+)', linha) 
            
            # EXTRAÇÃO DE MINAS DE OURO (Dados contextuais reais)
            match_loc = re.search(r'source_location="?([^"\s,]+(?:\s[^"\s,]+)*)"?', linha)
            match_app = re.search(r'application=([^\s]+)', linha)
            match_rule = re.search(r'rule_name=([^\s]+)', linha)
            
            if not (match_time and match_src and match_dst and match_dpt and match_act):
                continue
                
            try:
                tempo_obj = datetime.strptime(match_time.group(1), "%Y/%m/%d %H:%M:%S")
            except ValueError:
                continue
                
            src, dst, dpt, acao = match_src.group(1), match_dst.group(1), match_dpt.group(1), match_act.group(1).upper()
            
            ips_ativos_neste_lote.add(src)
            perfil = self.grafo_global[src]
            
            # Atualização das métricas do Grafo (Nós e Arestas)
            perfil.total_eventos += 1
            perfil.alvos_dst.add(dst) 
            perfil.portas_alvo[dpt] += 1
            
            # Armazenamento de metadados contextuais
            if match_loc: locais_ip[src] = match_loc.group(1)
            if match_app: apps_ip[src].add(match_app.group(1))
            if match_rule: regras_ip[src].add(match_rule.group(1))
            
            # Atualiza Série Temporal do IP
            if not perfil.primeiro_evento or tempo_obj < perfil.primeiro_evento:
                perfil.primeiro_evento = tempo_obj
            if not perfil.ultimo_evento or tempo_obj > perfil.ultimo_evento:
                perfil.ultimo_evento = tempo_obj

        # Salva o estado do grafo no disco (memoria_global_ips.json)
        self._salvar_memoria_disco()

        # 2. ANÁLISE DE GATILHOS E GERAÇÃO DO TOKEN ST-ALIGN
        resumos_st_align = []
        media_rede, std_rede = self._calcular_baseline_estatistico()
        
        # Limiares para filtragem dos 99% de tráfego comum
        limiar_burst_temporal = max(2.5, media_rede + (std_rede * 2)) 
        limiar_dispersao_espacial = 3 # Mais de 3 nós destino diferentes

        for ip_src in ips_ativos_neste_lote:
            perfil = self.grafo_global[ip_src]
            
            delta_t = max(1.0, (perfil.ultimo_evento - perfil.primeiro_evento).total_seconds())
            taxa_por_segundo = perfil.total_eventos / delta_t
            qtd_alvos_espaciais = len(perfil.alvos_dst)
            
            # --- HEURÍSTICA DE TRIAGEM (O filtro do seu orientador) ---
            # Se a taxa de eventos e a dispersão no grafo forem baixas, ignoramos para economizar IA
            if taxa_por_segundo <= limiar_burst_temporal and qtd_alvos_espaciais <= limiar_dispersao_espacial:
                continue 

            # Construção dos SPATIO-TEMPORAL CHARACTERS (Conforme o Artigo)
            if taxa_por_segundo > limiar_burst_temporal:
                char_temporal = f"[ANOMALIA TEMPORAL: BURST] Taxa de {taxa_por_segundo:.1f} ev/s supera baseline de {media_rede:.1f} ev/s."
            else:
                char_temporal = f"[TEMPO: NORMAL] Frequência dentro do desvio padrão."

            if qtd_alvos_espaciais > 1:
                char_espacial = f"[ANOMALIA ESPACIAL: MOVIMENTO DISTRIBUÍDO] Origem conectou-se a {qtd_alvos_espaciais} nós destino distintos no grafo."
            else:
                alvo_unico = list(perfil.alvos_dst)[0] if perfil.alvos_dst else "N/A"
                char_espacial = f"[ESPAÇO: FOCADO] Tráfego direcionado exclusivamente ao nó alvo {alvo_unico}."

            # Consolidação das "Minas de Ouro" de Contexto
            local = locais_ip.get(ip_src, "Desconhecido")
            apps = ", ".join(list(apps_ip[ip_src])[:2]) if apps_ip[ip_src] else "N/A"
            regras = ", ".join(list(regras_ip[ip_src])[:2]) if regras_ip[ip_src] else "N/A"
            porta_principal = max(perfil.portas_alvo, key=perfil.portas_alvo.get) if perfil.portas_alvo else "N/A"
            
            # TOKEN FINAL DE ALINHAMENTO (Enviado para a Camada 3)
            resumo_final = (
                f"ST-ALIGN EVENTO | ORIGEM: {ip_src} ({local}) | "
                f"COMPORTAMENTO: Atividade suspeita detectada via topologia e volume. | "
                f"ESPAÇO: {char_espacial} | "
                f"TEMPO: {char_temporal} | "
                f"CONTEXTO FIREWALL: Regras Disparadas [{regras}], Aplicações L7 [{apps}]. | "
                f"INFLUÊNCIA: Foco na porta {porta_principal}."
            )
            resumos_st_align.append(resumo_final)
            
        return resumos_st_align

    def processar_bloco(self, lote_linhas: list) -> RelatorioTriagem:
        resumos = self.extrair_caracteres_st(lote_linhas)
        incidentes_lista = []
        for resumo in resumos:
            match_ip = re.search(r"ORIGEM:\s*([^\s|]+)", resumo)
            ip_alvo = match_ip.group(1) if match_ip else "Desconhecido"
            incidentes_lista.append(Incidente(id_alvo=ip_alvo, padrao_ataque=resumo, dica_rag=""))
        return RelatorioTriagem(incidentes=incidentes_lista)

    def _salvar_memoria_disco(self):
        os.makedirs("resultados", exist_ok=True)
        with open("resultados/memoria_global_ips.json", "w", encoding="utf-8") as f:
            json.dump({ip: p.to_dict() for ip, p in self.grafo_global.items()}, f, indent=4)