# ... (restante do código do camada3_agente.py) ...

    # --- 3. A AÇÃO AGÊNTICA (MCP ATIVO) ---
    def executar_mcp_salvar_lote(self, relatorio_batch: RelatorioBatch, num_lote: int):
        if not relatorio_batch:
            return
            
        logger.info(f"=== [MCP] INICIANDO EXECUÇÃO DO LOTE {num_lote} ===")
        
        # 1. Salva o registro histórico (O Playbook)
        caminho_arquivo = f"../resultados/playbook_lote_{num_lote}.json"
        with open(caminho_arquivo, "w", encoding="utf-8") as f:
            json.dump(relatorio_batch.model_dump(), f, indent=4, ensure_ascii=False)
            
        # 2. O VERDADEIRO MCP: Execução de Ações baseada no Veredito
        for incidente in relatorio_batch.incidentes:
            veredito = incidente.veredito.upper()
            
            if veredito == "BLOQUEAR":
                self._mcp_tool_bloquear_ip(incidente.id_log)
                
            elif veredito == "MONITORAR":
                self._mcp_tool_adicionar_watchlist(incidente.id_log)
                
            else: # FALSO_POSITIVO
                logger.info(f"[MCP-Tool] Evento {incidente.id_log}: Classificado como Falso Positivo. Nenhuma ação tomada.")
                
        logger.info(f"=== [MCP] LOTE {num_lote} FINALIZADO E ARQUIVADO EM {caminho_arquivo} ===")

    # --- FERRAMENTAS DO MCP (TOOLS) ---
    
    def _mcp_tool_bloquear_ip(self, alvo: str):
        """Simula a chamada de API (Webhook) para o Firewall/Wazuh Active Response."""
        # NOTA: Em produção, aqui entraria um comando como:
        # requests.post("https://meu-firewall/api/block", json={"ip": ip_extraido})
        
        logger.warning(f"🚨 [MCP-Tool - FIREWALL] Executando DROP na borda da rede para o evento {alvo}!")

    def _mcp_tool_adicionar_watchlist(self, alvo: str):
        """Simula a adição do IP a uma lista de observação do SOC."""
        logger.info(f"👀 [MCP-Tool - SIEM] Evento {alvo} adicionado à Watchlist para monitoramento.")