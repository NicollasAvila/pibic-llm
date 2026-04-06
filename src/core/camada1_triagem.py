import os
import re
import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from pydantic import BaseModel
from typing import List

from config import ARQUIVO_MEMORIA, HORAS_TTL_MEMORIA

logger = logging.getLogger("Camada1_Triagem")

# === MODELOS DE DADOS (PYDANTIC) ===
class Incidente(BaseModel):
    id_alvo: str
    padrao_ataque: str
    dica_rag: str = ""
    veredito: str = ""       
    justificativa: str = ""
    nivel_confianca: str = ""
    is_red_team: bool = False

class RelatorioTriagem(BaseModel):
    incidentes: List[Incidente] = []

# === ESTRUTURA DO GRAFO NA RAM ===
class PerfilIP:
    def __init__(self):
        self.total_eventos = 0
        self.alvos_dst = set()
        self.portas_alvo = defaultdict(int)
        self.ultimo_acesso = None  # MÁGICA: Controla quando o IP deve ser apagado (TTL)

class TriagemEspacoTemporal:
    def __init__(self):
        self.ARQUIVO_MEMORIA = str(ARQUIVO_MEMORIA)
        self.grafo_global = defaultdict(PerfilIP)
        
        # Variáveis de Controle 24/7
        self.lotes_processados = 0 
        self.HORAS_TTL = HORAS_TTL_MEMORIA  # Puxado do Config Dinâmico
        
        # =================================================================
        # 🚀 OTIMIZAÇÃO: COMPILAÇÃO PRÉVIA DE REGEX E MÉTRICAS DLP (PIBIC)
        # =================================================================
        self.RE_TIME = re.compile(r'generated_time="([^"]+)"')
        self.RE_SRC  = re.compile(r'src_ip=([^\s]+)')
        self.RE_DST  = re.compile(r'dst_ip=([^\s]+)')
        self.RE_DPT  = re.compile(r'dst_port=(\d+)')
        self.RE_ACT  = re.compile(r'action=([a-zA-Z\-]+)')
        self.RE_LOC  = re.compile(r'source_location="?([^"\s,]+(?:\s[^"\s,]+)*)"?')
        self.RE_APP  = re.compile(r'application=([^\s]+)')
        self.RE_RULE = re.compile(r'rule_name=([^\s]+)')
        self.RE_BYT  = re.compile(r'(?:bytes_sent|bytes|sent)=(\d+)')

    def processar_bloco(self, lote_linhas: list) -> RelatorioTriagem:
        """Ponto de entrada chamado pelo Orquestrador."""
        if not lote_linhas:
            return RelatorioTriagem()
            
        incidentes_gerados = self._extrair_caracteres_st(lote_linhas)
        return RelatorioTriagem(incidentes=incidentes_gerados)

    def _extrair_caracteres_st(self, lote_linhas: list) -> list:
        ips_ativos_neste_lote = set()
        locais_ip = {}
        apps_ip = defaultdict(set)
        regras_ip = defaultdict(set)
        
        # Ocultamento Seguro (Blind Test) do Red Team e Controle de Volume de Dados
        red_team_ips = set()
        bytes_enviados_ip = defaultdict(int)
        
        # MEMÓRIA DE CURTO PRAZO: Contagem exclusiva deste bloco (Sliding Window)
        eventos_no_lote = defaultdict(int)
        tempo_inicial_lote = {}
        tempo_final_lote = {}
        maior_tempo_deste_lote = None
        
        # --- FASE 1: INGESTÃO E MAPEAMENTO ---
        for linha in lote_linhas:
            match_time = self.RE_TIME.search(linha)
            match_src  = self.RE_SRC.search(linha)
            match_dst  = self.RE_DST.search(linha)
            match_dpt  = self.RE_DPT.search(linha)
            match_act  = self.RE_ACT.search(linha)
            
            if not (match_time and match_src and match_dst and match_dpt and match_act): 
                continue
                
            try:
                tempo_obj = datetime.strptime(match_time.group(1), "%Y/%m/%d %H:%M:%S")
                if not maior_tempo_deste_lote or tempo_obj > maior_tempo_deste_lote:
                    maior_tempo_deste_lote = tempo_obj
            except ValueError:
                continue
                
            src = match_src.group(1)
            dst = match_dst.group(1)
            dpt = match_dpt.group(1)
            ips_ativos_neste_lote.add(src)
            
            # 1. Atualiza o Grafo de Longo Prazo (RAM)
            perfil = self.grafo_global[src]
            perfil.total_eventos += 1
            perfil.alvos_dst.add(dst)
            perfil.portas_alvo[dpt] += 1
            perfil.ultimo_acesso = tempo_obj  # Atualiza o relógio de vida deste IP
            
            # 2. Atualiza a Memória de Curto Prazo (para a matemática não diluir)
            eventos_no_lote[src] += 1
            
            match_loc = self.RE_LOC.search(linha)
            match_app = self.RE_APP.search(linha)
            match_rule = self.RE_RULE.search(linha)
            match_byt = self.RE_BYT.search(linha)
            
            if match_loc: locais_ip[src] = match_loc.group(1)
            if match_app: apps_ip[src].add(match_app.group(1))
            if match_byt: bytes_enviados_ip[src] += int(match_byt.group(1))
            
            if match_rule:
                regra_str = match_rule.group(1)
                
                # TESTE DUPLO CEGO (PIBIC)
                # O Pipeline burla o Drop porque viu a tag Alerta_RedTeam.
                # Agora, nós MARCAMOS que é um IP fake, mas NUNCA EXPOMOS isso nas regras pro LLM ler!
                if regra_str == "Alerta_RedTeam":
                    red_team_ips.add(src)
                else:
                    regras_ip[src].add(regra_str)
            
            if src not in tempo_inicial_lote or tempo_obj < tempo_inicial_lote[src]:
                tempo_inicial_lote[src] = tempo_obj
            if src not in tempo_final_lote or tempo_obj > tempo_final_lote[src]:
                tempo_final_lote[src] = tempo_obj

        # =================================================================
        # 🧹 COLETOR DE LIXO OTIMIZADO (Roda apenas quando a carga alivia)
        # =================================================================
        # FREIO APLICADO: Em vez de varrer milhões de IPs toda hora, 
        # a checagem só ocorre a cada 100 blocos e apenas se o tempo mudar.
        if maior_tempo_deste_lote and (self.lotes_processados % 100 == 0):
            tempo_limite = maior_tempo_deste_lote - timedelta(hours=self.HORAS_TTL)
            ips_para_remover = [
                ip for ip, p in self.grafo_global.items() 
                if p.ultimo_acesso and p.ultimo_acesso < tempo_limite
            ]
            for ip_morto in ips_para_remover:
                del self.grafo_global[ip_morto]
            if ips_para_remover:
                logger.debug(f"🧹 [Garbage Collector] Apagou {len(ips_para_remover)} IPs inativos há mais de {self.HORAS_TTL}h.")

        # =================================================================
        # 💾 CHECKPOINT SEGURO (Salva o grafo a cada 50 blocos processados)
        # =================================================================
        self.lotes_processados += 1
        if self.lotes_processados % 50 == 0:
            logger.info("💾 [Checkpoint] Salvando backup do Grafo Global no SSD...")
            self._salvar_memoria_disco()

        # --- FASE 2: RACIOCÍNIO ESPAÇO-TEMPORAL (Matemática Calibrada) ---
        lista_incidentes = []
        limiar_burst = 20.0     # Usuários normais abrem 15 con/st pra baixar 1 página. 20 é o limite.
        limiar_dispersao = 5    # Pingar mais de 5 máquinas na mesma subrede levanta suspeita
        limiar_exfiltracao_bytes = 10000000  # Acima de 10 MB enviados gera anomalia de DLP
        
        for ip_src in ips_ativos_neste_lote:
            perfil = self.grafo_global[ip_src]
            
            # A JANELA DESLIZANTE: Calcula a taxa (ev/s) USANDO APENAS O TEMPO DESTE LOTE!
            delta_t = max(1.0, (tempo_final_lote[ip_src] - tempo_inicial_lote[ip_src]).total_seconds())
            taxa_atual = eventos_no_lote[ip_src] / delta_t
            
            qtd_alvos_espaciais = len(perfil.alvos_dst)
            total_bytes = bytes_enviados_ip[ip_src]
            
            # Filtro Matemático Base: Se for tráfego lento e direcionado e pequeno volume, ignora.
            if taxa_atual <= limiar_burst and qtd_alvos_espaciais <= limiar_dispersao and total_bytes < limiar_exfiltracao_bytes:
                continue

            # Construção das Strings de Contexto para o LLM
            if taxa_atual > limiar_burst:
                char_temporal = f"[BURST AGUDO] Taxa atual de {taxa_atual:.1f} ev/s."
            else:
                char_temporal = f"[TEMPO NORMAL] Frequência baixa neste instante."

            if qtd_alvos_espaciais >= limiar_dispersao:
                char_espacial = f"[DISPERSÃO ALTA] Este IP já escaneou ou tocou {qtd_alvos_espaciais} IPs internos lateralmente."
            else:
                char_espacial = f"[FOCADO] Tráfego direcionado a um alvo quase que exclusivamente."
                
            char_volume = ""
            if total_bytes >= limiar_exfiltracao_bytes:
                mb_enviado = total_bytes / (1024*1024)
                char_volume = f" | [⚠️ DLP ALERTA] Detectado pico anômalo de Upload de {mb_enviado:.1f} Megabytes transferidos para fora!"

            local = locais_ip.get(ip_src, "Desconhecido")
            apps = ", ".join(list(apps_ip[ip_src])[:2]) if apps_ip[ip_src] else "N/A"
            regras = ", ".join(list(regras_ip[ip_src])[:2]) if regras_ip[ip_src] else "Variaveis"
            porta_principal = max(perfil.portas_alvo, key=perfil.portas_alvo.get) if perfil.portas_alvo else "N/A"
            
            # Geração do Prompt Denso SEm POLUIR COM DADOS FACCIONADOS (Blind Test)
            st_align_texto = (
                f"ST-ALIGN | ORIGEM: {ip_src} ({local}) | EVENTOS TOTAIS HOJE: {perfil.total_eventos} | "
                f"ESPAÇO: {char_espacial} | TEMPO: {char_temporal}{char_volume} | "
                f"FIREWALL: Regras [{regras}], App [{apps}]. ALVO CENTRAL: Porta {porta_principal}."
            )
            
            # Monta o objeto Pydantic com o rastro cego (is_red_team) 
            incidente = Incidente(
                id_alvo=ip_src,
                padrao_ataque=st_align_texto,
                is_red_team=(ip_src in red_team_ips)
            )
            lista_incidentes.append(incidente)
            
        return lista_incidentes

    def _salvar_memoria_disco(self):
        """Faz um dump assíncrono do dicionário na memória RAM para o SSD."""
        try:
            os.makedirs(os.path.dirname(self.ARQUIVO_MEMORIA), exist_ok=True)
            # Converte o Grafo (Set) para formatos serializáveis em JSON
            dados_salvar = {}
            for ip, perfil in self.grafo_global.items():
                dados_salvar[ip] = {
                    "total_eventos": perfil.total_eventos,
                    "alvos_dst": list(perfil.alvos_dst),
                    "portas_alvo": dict(perfil.portas_alvo),
                    "ultimo_acesso": perfil.ultimo_acesso.strftime("%Y-%m-%d %H:%M:%S") if perfil.ultimo_acesso else None
                }
            with open(self.ARQUIVO_MEMORIA, "w", encoding="utf-8") as f:
                json.dump(dados_salvar, f, indent=4)
        except Exception as e:
            logger.error(f"Falha ao salvar o checkpoint do grafo: {e}")