STRINGS = {
    # General
    "error": "Error",
    "done": "Done",
    "unknown": "Unknown",
    "cancelled": "CANCELLED",
    "scan_cancelled": "Scan cancelled by user.",
    "no_results": "No results available.",
    "no_records": "No records",

    # Files / system
    "file_not_found": "File not found",
    "cannot_open_file": "Could not open file",
    "csv_save_error": "Error saving CSV",

    # Tabs
    "tab_ip": "IP",
    "tab_hash": "Hash",
    "tab_domain": "Domain",

    # Buttons
    "btn_copy": "Copy",
    "btn_export": "Export",
    "btn_cancel": "Cancel",
    "btn_check_ip": "Check IP",
    "btn_check_hash": "Check Hash",
    "btn_check_domain": "Check Domain",

    # Inputs
    "paste_ips": "Paste IPs below:",
    "paste_hashes": "Paste hashes below:",
    "paste_domains": "Paste domains below:",

    # Toggles
    "pre_analysis": "Pre-analysis",
    "has_mss": "Customer has MSS?",

    # Status
    "checking_ips": "Checking IPs",
    "checking_hashes": "Checking hashes",
    "checking_domains": "Checking domains",
    "checking_domains": "Checking domains",

    # IP validation
    "invalid_ip": "Invalid IP",
    "private_ip": "Private IP",
    "no_valid_public_ip": "No valid public IP provided.",

    # Hash
    "invalid_hashes_title": "Invalid hashes",
    "invalid_hashes_msg": "The following hashes are invalid:",
    "no_valid_hash": "No valid hash provided.",
    "hash_scan_finished": "Hash scan finished.",
    "hash_bad_mss_one": (
        "Malicious file detected.\n"
        "A ticket was opened with MSS to perform a full scan on the host: "
    ),
    "hash_bad_mss_many": (
        "Malicious files detected.\n"
        "A ticket was opened with MSS to perform a full scan on the host: "
    ),
    "hash_bad_no_mss_one": (
        "Malicious file detected.\n"
        "We recommend performing a full scan on the host to remove any malware traces."
    ),
    "hash_bad_no_mss_many": (
        "Malicious files detected.\n"
        "We recommend performing a full scan on the host to remove any malware traces."
    ),
    "hash_clean_one": "No malicious reputation found for the queried hash.",
    "hash_clean_many": "No malicious reputation found for the queried hashes.",

    # URL / Domain
    "no_domain": "No domain provided.",
    "domain_scan_finished": "Domain scan finished.",
    "domain_ips_one": "Associated IP for the domain",
    "domain_ips_many": "Associated IPs for the domain",
    "domain_no_ip": "Could not resolve IPs for the domain.",
    "url_bad_mss_one": (
        "Domain with bad reputation detected.\n"
        "A ticket was opened with MSS to block the following domain: "
    ),
    "url_bad_mss_many": (
        "Domains with bad reputation detected.\n"
        "A ticket was opened with MSS to block the following domains: "
    ),
    "url_bad_no_mss_one": (
        "Domain with bad reputation detected.\n"
        "We recommend blocking or inspecting the traffic."
    ),
    "url_bad_no_mss_many": (
        "Domains with bad reputation detected.\n"
        "We recommend blocking or inspecting the traffic."
    ),
    "url_clean_one": (
        "No malicious reputation indicators were found for the queried domain."
    ),
    "url_clean_many": (
        "No malicious reputation indicators were found for the queried domains."
    ),

    # Reputation
    "reputation_bad": "Has bad reputation",
    "reputation_clean": "Does NOT have bad reputation",
    "whitelisted": "listed in the AbuseIPDB whitelist",
    "reputation_whitelisted_bad": (
        "WARNING - Listed in the AbuseIPDB whitelist, "
        "but bad reputation was found on other sources"
    ),

    # Scores
    "vt_score": "VirusTotal score",
    "ibm_score": "IBM score",
    "alien_score": "AlienVault",

    # Hash details
    "file_name": "File name",
    "last_analysis_vt": "Last analysis on VirusTotal",
    "joesandbox_found": "JOESandbox report found",

    # IP analysis
    "ip_bad_mss_one": (
        "IP with bad reputation: {lista}\n"
        "A ticket was opened with MSS to block the following IP: "
    ),
    "ip_bad_mss_many": (
        "IPs with bad reputation: {lista}\n"
        "A ticket was opened with MSS to block the following IPs: "
    ),
    "ip_bad_no_mss_one": (
        "IP with bad reputation: {lista}\n"
        "We recommend blocking the IP on the firewall due to its reputation history."
    ),
    "ip_bad_no_mss_many": (
        "IPs with bad reputation: {lista}\n"
        "We recommend blocking the IPs on the firewall due to their reputation history."
    ),
    "ip_whitelist_review_one": (
        "The IP {lista} is listed in the AbuseIPDB whitelist, but bad reputation was "
        "found on other sources (VirusTotal and/or IBM X-Force).\n"
        "Being whitelisted on AbuseIPDB does not override the detections from the other "
        "sources. We recommend validating whether the IP is legitimate and expected in "
        "the environment before dismissing the alert."
    ),
    "ip_whitelist_review_many": (
        "The following IPs are listed in the AbuseIPDB whitelist, but bad reputation was "
        "found on other sources (VirusTotal and/or IBM X-Force): {lista}\n"
        "Being whitelisted on AbuseIPDB does not override the detections from the other "
        "sources. We recommend validating whether the IPs are legitimate and expected in "
        "the environment before dismissing the alert."
    ),
    "ip_clean_one": (
        "No malicious reputation indicators were found for the queried IP."
    ),
    "ip_clean_many": (
        "No malicious reputation indicators were found for the queried IPs."
    ),

    # Folders / files
    "select_folder_hash": "Select folder to save hash results",
    "select_folder_url": "Select folder to save URL results",

    # Associated IP error
    "error_checking_associated_ip": "Error checking associated IP",

    # Update
    "update_available": "Update available",
    "new_version_available": "A new version of IP Shark is available: {version}",
    "whats_new": "What's new:",
    "cannot_load_release_notes": "Could not load release notes.",
    "download_github": "🔗 Click here to download from GitHub",

    # Scan end
    "scan_finished": "Scan finished successfully.",

    # IP labels (legacy standard)
    "abuseipdb_score": "AbuseIPDB score",
    "domain_label": "Domain name",
    "country_city_label": "Country and city",
    "last_report_label": "Last report on AbuseIPDB",
    
    # Toggles
    "toggle_ibm": "IBM X-Force",
    "toggle_pre_analysis": "Pre-analysis",
    "toggle_has_mss": "Customer has MSS?",

    # Config
    "btn_config_api": "🗝 Configure API",
    "close": "Close",
    "cfg_title": "Configure API keys",
    "cfg_intro": (
        "Keys are stored on this computer only, encrypted by Windows with your "
        "account credentials. No other account or machine can read them."
    ),
    "cfg_intro_sem_cripto": (
        "WARNING: this system does not provide Windows encryption (DPAPI). "
        "Keys will be stored unencrypted, with access restricted to your user."
    ),
    "cfg_col_service": "Service",
    "cfg_col_key": "API key",
    "cfg_configured": "configured",
    "cfg_not_configured": "not configured",
    "cfg_show": "Show",
    "cfg_hide": "Hide",
    "cfg_get_key": "Get key",
    "cfg_save": "Save",
    "cfg_cancel": "Cancel",
    "cfg_saved_title": "Keys saved",
    "cfg_saved": "Keys securely saved to:\n{caminho}",
    "cfg_save_error": "Could not save the keys",
    "cfg_erase": "Erase saved keys",
    "cfg_erase_confirm": (
        "This removes every API key saved on this computer.\n\nDo you want to continue?"
    ),
    "cfg_erased": "Saved keys were removed.",
    "cfg_legacy_found": (
        "We found the old config/api.env file, which stores keys in plain text. "
        "Your keys were already imported into the encrypted vault — the file is no longer "
        "used and can be removed."
    ),
    "cfg_legacy_delete": "Remove old file",
    "cfg_legacy_confirm": "Permanently remove the file:\n{caminho}?",
    "cfg_legacy_deleted": "Old file removed.",
    "cfg_legacy_delete_error": "Could not remove the old file",

    # CSV headers
    "csv_ip": "IP",
    "csv_hash": "Hash",
    "csv_domain": "Domain",
    "csv_abuse_score": "AbuseIPDB score",
    "csv_vt_score": "VirusTotal score",
    "csv_ibm_score": "IBM score",
    "csv_alien_score": "AlienVault",
    "csv_country": "Country",
    "csv_city": "City",
    "csv_last_report": "Last report",
    "csv_file_name": "File name",
    "csv_last_analysis": "Last analysis",
    "csv_abuse_link": "AbuseIPDB link",
    "csv_vt_link": "VirusTotal link",
    "csv_ibm_link": "IBM link",
    "csv_alien_link": "AlienVault link",
    "csv_joe_link": "JoeSandbox link",
    "toggle_check_ips": "Check associated IPs",
    "csv_sheet_domains": "Domains",
    "csv_sheet_ips_prefix": "IPs - ",
    
    "scan_already_running_ip": "An IP scan is already running. Please wait for it to finish.",
    "scan_already_running_hash": "A Hash scan is already running. Please wait for it to finish.",
    "scan_already_running_domain": "A Domain scan is already running. Please wait for it to finish."
    
}