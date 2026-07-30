STRINGS = {
    # Gerais
    "error": "Erro",
    "done": "Concluído",
    "unknown": "Desconhecido",
    "cancelled": "CANCELADO",
    "scan_cancelled": "Consulta interrompida pelo usuário.",
    "no_results": "Nenhum resultado disponível.",
    "no_records": "Sem registros",

    # Arquivos / sistema
    "file_not_found": "Arquivo não encontrado",
    "cannot_open_file": "Não foi possível abrir o arquivo",
    "csv_save_error": "Erro ao salvar CSV",

    # Tabs
    "tab_ip": "IP",
    "tab_hash": "Hash",
    "tab_domain": "Domínio",

    # Botões
    "btn_copy": "Copiar resultados",
    "btn_export": "Exportar",
    "btn_cancel": "Cancelar",
    "btn_check_ip": "Consultar IP",
    "btn_check_hash": "Consultar Hash",
    "btn_check_domain": "Consultar Domínio",

    # Inputs
    "paste_ips": "Cole os IPs abaixo:",
    "paste_hashes": "Cole os hashes abaixo:",
    "paste_domains": "Cole os domínios abaixo:",

    # Status
    "checking_ips": "Consultando IPs",
    "checking_hashes": "Consultando Hashes",
    "checking_domains": "Consultando Domínios",

    # IP validation
    "invalid_ip": "IP inválido",
    "private_ip": "IP privado",
    "no_valid_public_ip": "Nenhum IP público válido informado.",

    # Hash
    "invalid_hashes_title": "Hashes inválidos",
    "invalid_hashes_msg": "Os seguintes hashes são inválidos:",
    "no_valid_hash": "Nenhum hash válido informado.",
    "hash_scan_finished": "Consulta de hashes finalizada.",
    "hash_bad_mss_one": (
        "Arquivo malicioso detectado.\n"
        "Um chamado foi aberto com o MSS para que um full scan seja efetuado no host: "
    ),
    "hash_bad_mss_many": (
        "Arquivos maliciosos detectados.\n"
        "Um chamado foi aberto com o MSS para que um full scan seja efetuado no host: "
    ),
    "hash_bad_no_mss_one": (
        "Arquivo malicioso detectado.\n"
        "Recomendamos a execução de um full scan no host para eliminar quaisquer vestígios de malware."
    ),
    "hash_bad_no_mss_many": (
        "Arquivos maliciosos detectados.\n"
        "Recomendamos a execução de um full scan no host para eliminar quaisquer vestígios de malware."
    ),
    "hash_clean_one": (
        "Nenhum indício de reputação maliciosa foi encontrado para o hash consultado."
    ),
    "hash_clean_many": (
        "Nenhum indício de reputação maliciosa foi encontrado para os hashes consultados."
    ),

    # URL / Domínio
    "no_domain": "Nenhum domínio informado.",
    "invalid_domain": "domínio inválido",
    "no_valid_domain": "Nenhum domínio válido informado.",
    "domain_scan_finished": "Consulta de domínio finalizada.",
    "domain_ips_one": "IP associado ao domínio",
    "domain_ips_many": "IPs associados ao domínio",
    "domain_no_ip": "Não foi possível resolver IP para o domínio.",
    "url_bad_mss_one": (
        "Domínio com má reputação detectada.\n"
        "Um chamado foi aberto com o MSS para efetuar o bloqueio do Domínio: "
    ),
    "url_bad_mss_many": (
        "Domínios com má reputação detectada.\n"
        "Um chamado foi aberto com o MSS para efetuar o bloqueio dos Domínios: "
    ),
    "url_bad_no_mss_one": (
        "Domínio com má reputação detectada.\n"
        "Recomendamos o bloqueio ou inspeção do tráfego."
    ),
    "url_bad_no_mss_many": (
        "Domínios com má reputação detectada.\n"
        "Recomendamos o bloqueio ou inspeção do tráfego."
    ),
    "url_clean_one": (
        "Nenhum indício de reputação maliciosa foi encontrado para o Domínio consultado."
    ),
    "url_clean_many": (
        "Nenhum indício de reputação maliciosa foi encontrado para os Domínios consultados."
    ),

    # Reputação
    "reputation_bad": "Possui má reputação",
    "reputation_clean": "NÃO possui má reputação",
    "whitelisted": "consta em whitelist do AbuseIPDB",
    "reputation_whitelisted_bad": (
        "ATENÇÃO - Consta em whitelist do AbuseIPDB, "
        "porém foi identificada má reputação em outras bases"
    ),

    # Scores
    "vt_score": "Score VirusTotal",
    "ibm_score": "Score IBM",
    "alien_score": "AlienVault",
    "md_score": "Score MetaDefender",
    "count_pulse": "pulso",
    "count_pulses": "pulsos",
    "otx_family": "Família de malware",
    "otx_adversary": "Grupo atribuído",
    "otx_pulses": "Relatado como",
    "otx_known_good": "Consta em lista de legítimos do OTX",

    # Hash details
    "file_name": "Nome do arquivo",
    "last_analysis_vt": "Última análise no VirusTotal",

    # JoeSandbox
    "joe_score": "JoeSandbox",
    "joe_verdict_malicious": "Malicioso",
    "joe_verdict_suspicious": "Suspeito",
    "joe_verdict_clean": "Limpo",
    "joe_av": "AV {pct}%",
    "joe_count_one": "{n} análise",
    "joe_count_many": "{n} análises",
    "joe_count_verdict": "{n} com este veredito",
    "joe_class_evad": "Evasivo",
    "joe_behavior": "Comportamento observado",
    "joe_malwareconfig": (
        "Configuração de malware extraída pelo sandbox (indica C2 identificado)"
    ),
    "joe_flag_malwareconfig": "contém configuração de malware",
    "joe_flag_injects": "injeta código em processos",
    "joe_flag_drops_pe": "grava executáveis em disco",
    "joe_flag_creates_files": "cria arquivos maliciosos",
    "joe_flag_registry": "grava chaves de registro",
    "joe_flag_http": "gera tráfego HTTP",
    "joe_flag_traffic": "gera tráfego de rede",
    "joe_flag_processes": "cria múltiplos processos",
    "joe_flag_email": "contém anexo de e-mail",
    "joe_flag_native_cmd": "executa comandos nativos",
    "joe_flag_sends_sms": "envia SMS",
    "joe_flag_recv_sms": "recebe SMS",
    "joe_flag_reboot": "reinicia o dispositivo",
    "joe_flag_expired": "amostra expirada",

    # IP analysis
    "ip_bad_mss_one": (
        "IP com má reputação: {lista}\n"
        "Um chamado foi aberto com o MSS para efetuar o bloqueio do IP: "
    ),
    "ip_bad_mss_many": (
        "IPs com má reputação: {lista}\n"
        "Um chamado foi aberto com o MSS para efetuar o bloqueio dos IPs: "
    ),
    "ip_bad_no_mss_one": (
        "IP com má reputação: {lista}\n"
        "Recomendamos o bloqueio do IP no firewall devido ao seu histórico de má reputação."
    ),
    "ip_bad_no_mss_many": (
        "IPs com má reputação: {lista}\n"
        "Recomendamos o bloqueio dos IPs no firewall devido ao seu histórico de má reputação."
    ),
    "ip_clean_one": (
        "Nenhum indício de reputação maliciosa foi encontrado para o IP consultado."
    ),
    "ip_clean_many": (
        "Nenhum indício de reputação maliciosa foi encontrado para os IPs consultados."
    ),
    "ip_whitelist_review_one": (
        "O IP {lista} consta em whitelist do AbuseIPDB, porém com má reputação "
        "identificada em outras bases (VirusTotal e/ou IBM X-Force).\n"
        "A presença em whitelist do AbuseIPDB não invalida as detecções das demais bases. "
        "Recomendamos validar se o IP é legítimo e esperado no ambiente antes de "
        "descartar o alerta."
    ),
    "ip_whitelist_review_many": (
        "Os IPs a seguir constam em whitelist do AbuseIPDB, porém com má reputação "
        "identificada em outras bases (VirusTotal e/ou IBM X-Force): {lista}\n"
        "A presença em whitelist do AbuseIPDB não invalida as detecções das demais bases. "
        "Recomendamos validar se os IPs são legítimos e esperados no ambiente antes de "
        "descartar o alerta."
    ),

    # Pastas / arquivos
    "select_folder": "Selecione a pasta para salvar a planilha",
    "select_folder_hash": "Selecione a pasta para salvar os resultados de hash",
    "select_folder_url": "Selecione a pasta para salvar os resultados de URL",

    # Erros IP associados
    "error_checking_associated_ip": "Erro ao consultar IP associado",
    "error_processing_ip": "Erro ao processar IP",

    # Atualização
    "update_available": "Atualização disponível",
    "new_version_available": "Uma nova versão do IP Shark está disponível: {version}",
    "whats_new": "Novidades:",
    "cannot_load_release_notes": "Não foi possível carregar as novidades.",
    "download_github": "🔗 Clique aqui para baixar no GitHub",

    # Scan final
    "scan_finished": "Consulta finalizada com sucesso.",

    # Labels IP (padrão antigo)
    "abuseipdb_score": "Score no AbuseIPDB",
    "domain_label": "Nome de domínio",
    "country_city_label": "País e cidade",
    "last_report_label": "Último relatório no AbuseIPDB",
    
    # Toggles
    "section_input": "Entrada",
    "section_sources": "Fontes consultadas",
    "section_report": "Relatório",
    "section_results": "Resultados",
    "toggle_pre_analysis": "Incluir Texto de Análise",
    "toggle_has_mss": "Incluir Texto de MSS",

    # Personalizar pesquisa
    "btn_customize": "⚙ Personalizar pesquisa",
    "src_title": "Fontes consultadas",
    "src_intro": (
        "Desmarque o que não quer consultar. Fonte desmarcada não é consultada e não "
        "deixa o resultado incompleto — útil quando uma base está fora do ar ou quando "
        "a pressa não permite esperar as consultas por navegador."
    ),
    "src_fast": "API",
    "src_slow": "navegador, mais lento",
    "src_all": "Marcar todas",
    "src_only_fast": "Só as rápidas",
    "src_apply": "Aplicar",
    "src_none": "Deixe pelo menos uma fonte marcada.",
    "src_summary_off": "sem {fontes}",
    "source_abuse": "AbuseIPDB",
    "source_vt": "VirusTotal",
    "source_md": "MetaDefender",
    "source_alien": "AlienVault",
    "source_ipinfo": "IPinfo (localização)",
    "source_ibm": "IBM X-Force",
    "source_joe": "JoeSandbox",
    "source_assoc_ips": "IPs associados ao domínio",

    # Config
    "btn_config_api": "🗝 Configurar API",
    "close": "Fechar",
    "cfg_title": "Configurar chaves de API",
    "cfg_intro": (
        "As chaves são salvas apenas neste computador, criptografadas pelo Windows "
        "com as credenciais da sua conta. Nenhuma outra conta ou máquina consegue lê-las."
    ),
    "cfg_intro_sem_cripto": (
        "ATENÇÃO: este sistema não oferece a criptografia do Windows (DPAPI). "
        "As chaves serão gravadas sem criptografia, com acesso restrito ao seu usuário."
    ),
    "cfg_col_service": "Serviço",
    "cfg_col_key": "Chave de API",
    "cfg_configured": "configurada",
    "cfg_not_configured": "não configurada",
    "cfg_show": "Mostrar",
    "cfg_hide": "Ocultar",
    "cfg_get_key": "Obter chave",
    "cfg_test": "Testar conexão",
    "cfg_testing": "testando…",
    "cfg_test_ok": "respondeu",
    "cfg_test_rejected": "chave recusada",
    "cfg_test_none": "Preencha ao menos uma chave para testar.",
    "cfg_test_cost": "Cada teste gasta uma consulta da cota de cada API.",
    "quota_footer": "Cota restante hoje",
    "history_title": "Histórico da sessão",
    "history_empty": "As consultas desta sessão aparecem aqui. Nada é gravado em disco.",
    "history_restored": "Resultado recuperado do histórico da sessão.",
    "cfg_save": "Salvar",
    "cfg_cancel": "Cancelar",
    "cfg_saved_title": "Chaves salvas",
    "cfg_saved": "Chaves salvas com segurança em:\n{caminho}",
    "cfg_save_error": "Não foi possível salvar as chaves",
    "cfg_erase": "Apagar chaves salvas",
    "cfg_erase_confirm": (
        "Isto remove todas as chaves de API salvas neste computador.\n\nDeseja continuar?"
    ),
    "cfg_erased": "As chaves salvas foram removidas.",
    "cfg_legacy_found": (
        "Encontramos o arquivo antigo config/api.env, que guarda as chaves em texto puro. "
        "Suas chaves já foram importadas para o cofre criptografado — o arquivo não é mais usado "
        "e pode ser removido."
    ),
    "cfg_legacy_delete": "Remover arquivo antigo",
    "cfg_legacy_confirm": "Remover definitivamente o arquivo:\n{caminho}?",
    "cfg_legacy_deleted": "Arquivo antigo removido.",
    "cfg_legacy_delete_error": "Não foi possível remover o arquivo antigo",

    # Cabeçalhos CSV
    "csv_ip": "IP",
    "csv_hash": "Hash",
    "csv_domain": "Domínio",
    "csv_verdict": "Veredito",
    "csv_abuse_score": "Score AbuseIPDB",
    "csv_vt_score": "Score VirusTotal",
    "csv_ibm_score": "Score IBM",
    "csv_alien_score": "AlienVault",
    "csv_md_score": "MetaDefender",
    "csv_country": "País",
    "csv_city": "Cidade",
    "csv_last_report": "Última Denúncia",
    "csv_file_name": "Nome do Arquivo",
    "csv_last_analysis": "Última Análise",
    "csv_abuse_link": "Link AbuseIPDB",
    "csv_vt_link": "Link VirusTotal",
    "csv_ibm_link": "Link IBM",
    "csv_alien_link": "Link AlienVault",
    "csv_md_link": "Link MetaDefender",
    "csv_joe_link": "Link JoeSandbox",
    "csv_joe_verdict": "Veredito JoeSandbox",
    "csv_joe_class": "Classificação JoeSandbox",
    "csv_joe_behavior": "Comportamento JoeSandbox",
    
    # Tabela de resultados
    "col_verdict": "Veredito",
    "col_abuse": "AbuseIPDB",
    "col_vt": "VirusTotal",
    "col_ibm": "X-Force",
    "col_alien": "AlienVault",
    "col_md": "MetaDefender",
    "col_joe": "JoeSandbox",
    "col_country": "País",
    "col_file": "Arquivo",
    "verdict_clean": "● Limpo",
    "verdict_whitelisted": "● Limpo (whitelist)",
    "verdict_review": "▲ Revisar",
    "verdict_bad": "✖ Malicioso",
    "verdict_unknown": "○ Indisponível",
    "verdict_incomplete": "▲ Análise incompleta",
    "verdict_no_records": "○ Sem registros",
    "no_records_one": (
        "O indicador a seguir não foi encontrado em nenhuma das bases consultadas: {lista}\n"
        "A ausência de registro não confirma que o indicador é legítimo."
    ),
    "no_records_many": (
        "Os indicadores a seguir não foram encontrados em nenhuma das bases consultadas: {lista}\n"
        "A ausência de registro não confirma que os indicadores são legítimos."
    ),

    # Pool de navegadores do X-Force
    "drivers_degraded": (
        "Apenas {vivos} de {total} navegadores do IBM X-Force iniciaram. "
        "As consultas ao X-Force vão funcionar, mas mais devagar."
    ),
    "drivers_none": (
        "Nenhum navegador do IBM X-Force pôde ser iniciado — essas consultas serão "
        "marcadas como indisponíveis. Verifique se o Google Chrome está instalado e se "
        "o download do ChromeDriver não está bloqueado na rede."
    ),

    # Estados por fonte
    "source_unavailable": "falha na consulta",
    "source_no_key": "chave não configurada",
    "source_quota": "cota da API esgotada",
    "source_no_data": "sem registros",
    "sources_incomplete": "Análise incompleta — não responderam: {fontes}",
    "quota_warning": (
        "ATENÇÃO: a cota de alguma API se esgotou durante a varredura ({fontes}). "
        "Os itens marcados como incompletos NÃO foram verificados nessas bases — "
        "repita a consulta depois que a cota renovar."
    ),
    "quota_retry_after": "{fonte}: a API pediu para repetir em ~{tempo}.",
    "incomplete_review": (
        "Os itens a seguir não puderam ser verificados em todas as bases: {lista}\n"
        "A ausência de detecção aqui não significa que o indicador é limpo. "
        "Repita a consulta antes de liberar."
    ),
    "warnings_not_copied": "⚠ AVISOS PARA O ANALISTA — não entram no texto copiado:",
    "detail_hint": "Selecione uma linha para ver os detalhes e os links.",
    "count_valid": "válidos",
    "count_invalid": "inválidos",
    "count_private": "privados",
    "skipped_items": "Ignorados",
    "progress_done": "{feitos}/{total}",
    "associated_to_domain": "associado ao domínio",

    "csv_sheet_results": "Resultados",
    "csv_sheet_domains": "Domínios",
    "csv_sheet_ips_prefix": "IPs - ",
    
    "scan_already_running_ip": "Já existe uma consulta de IP em andamento. Aguarde a finalização.",
    "scan_already_running_hash": "Já existe uma consulta de Hash em andamento. Aguarde a finalização.",
    "scan_already_running_domain": "Já existe uma consulta de Domínio em andamento. Aguarde a finalização."

}