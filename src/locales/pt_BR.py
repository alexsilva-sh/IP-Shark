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
    "btn_copy": "Copiar",
    "btn_export": "Exportar",
    "btn_cancel": "Cancelar",
    "btn_check_ip": "Consultar IP",
    "btn_check_hash": "Consultar Hash",
    "btn_check_domain": "Consultar Domínio",

    # Inputs
    "paste_ips": "Cole os IPs abaixo:",
    "paste_hashes": "Cole os hashes abaixo:",
    "paste_domains": "Cole os domínios abaixo:",

    # Toggles
    "pre_analysis": "Pré-análise",
    "has_mss": "Cliente tem MSS?",

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
    "hash_bad_mss": (
        "Arquivo malicioso detectado.\n"
        "Um chamado foi aberto com o MSS para que um full scan seja efetuado no host: "
    ),
    "hash_bad_no_mss": (
        "Arquivo malicioso detectado.\n"
        "Recomendamos a execução de um full scan no host para eliminar quaisquer vestígios de malware."
    ),
    "hash_clean": "Nenhum indício de reputação maliciosa foi encontrado para o hash consultado.",

    # URL / Domínio
    "no_domain": "Nenhum domínio informado.",
    "domain_scan_finished": "Consulta de domínio finalizada.",
    "domain_ips": "IP(s) associados ao domínio",
    "domain_no_ip": "Não foi possível resolver IP para o domínio.",
    "url_bad_mss": (
        "Domínio(s) com má reputação detectada.\n"
        "Um chamado foi aberto com o MSS para efetuar o bloqueio para o(s) Domínio(s): "
    ),
    "url_bad_no_mss": (
        "Domínio(s) com má reputação detectada.\n"
        "Recomendamos o bloqueio ou inspeção do tráfego."
    ),
    "url_clean": (
        "Nenhum indício de reputação maliciosa foi encontrado para os Domínios consultados."
    ),

    # Reputação
    "reputation_bad": "Possui má reputação",
    "reputation_clean": "NÃO possui má reputação",

    # Scores
    "vt_score": "Score VirusTotal",
    "ibm_score": "Score IBM",
    "alien_score": "AlienVault",

    # Hash details
    "file_name": "Nome do arquivo",
    "last_analysis_vt": "Última análise no VirusTotal",
    "joesandbox_found": "Foi encontrado relatório no JOESandbox",

    # IP analysis
    "ip_bad_mss": (
        "IP(s) com má reputação: {lista}\n"
        "Um chamado foi aberto com o MSS para efetuar o bloqueio do(s) IP(s): "
    ),
    "ip_bad_no_mss": (
        "IP(s) com má reputação: {lista}\n"
        "Recomendamos o bloqueio do IP no firewall devido ao seu histórico de má reputação."
    ),
    "ip_clean": (
        "Nenhum indício de reputação maliciosa foi encontrado para o(s) IP(s) consultados."
    ),

    # Pastas / arquivos
    "select_folder_hash": "Selecione a pasta para salvar os resultados de hash",
    "select_folder_url": "Selecione a pasta para salvar os resultados de URL",

    # Erros IP associados
    "error_checking_associated_ip": "Erro ao consultar IP associado",

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
    "toggle_ibm": "IBM X-Force",
    "toggle_pre_analysis": "Pré-análise",
    "toggle_has_mss": "Cliente tem MSS?",

    # Config
    "btn_config_api": "🗝 Configurar API",
    
    # Cabeçalhos CSV
    "csv_ip": "IP",
    "csv_hash": "Hash",
    "csv_domain": "Domínio",
    "csv_abuse_score": "Score AbuseIPDB",
    "csv_vt_score": "Score VirusTotal",
    "csv_ibm_score": "Score IBM",
    "csv_alien_score": "AlienVault",
    "csv_country": "País",
    "csv_city": "Cidade",
    "csv_last_report": "Última Denúncia",
    "csv_file_name": "Nome do Arquivo",
    "csv_last_analysis": "Última Análise",
    "csv_abuse_link": "Link AbuseIPDB",
    "csv_vt_link": "Link VirusTotal",
    "csv_ibm_link": "Link IBM",
    "csv_alien_link": "Link AlienVault",
    "csv_joe_link": "Link JoeSandbox",
    
    "toggle_check_ips": "Consultar IPs associados",
    "csv_sheet_domains": "Domínios",
    "csv_sheet_ips_prefix": "IPs - ",
    
    "scan_already_running_ip": "Já existe uma consulta de IP em andamento. Aguarde a finalização.",
    "scan_already_running_hash": "Já existe uma consulta de Hash em andamento. Aguarde a finalização.",
    "scan_already_running_domain": "Já existe uma consulta de Domínio em andamento. Aguarde a finalização."

}