"""Regras que transformam as respostas das fontes em veredito."""
import ipaddress
import unicodedata
from datetime import datetime, timedelta

from core.api import (
    ESTADOS_SEM_RESPOSTA,
    FONTE_COTA,
    FONTE_INDISPONIVEL,
    FONTE_OK,
    FONTE_SEM_DADOS,
    safe_get,
)


def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def remover_acentos(texto):
    if isinstance(texto, str):
        return "".join(c for c in unicodedata.normalize("NFD", texto)
                       if unicodedata.category(c) != "Mn")
    return texto


def get_domain_from_abuseipdb(abuseipdb_result):
    try:
        return remover_acentos(abuseipdb_result["data"].get("domain", "N/A")) if abuseipdb_result else "N/A"
    except KeyError:
        return "N/A"


def is_whitelisted_abuseipdb(abuseipdb_result):
    if not abuseipdb_result:
        return False
    try:
        return bool(abuseipdb_result["data"].get("isWhitelisted", False))
    except (KeyError, TypeError, AttributeError):
        return False


def classificar_ibm(valor):
    """Traduz o retorno do scraping do X-Force para um estado de fonte."""
    if valor is None:
        return None      # fonte nao consultada
    bruto = str(valor).strip().lower()
    if bruto == "error":
        return FONTE_INDISPONIVEL
    if bruto == "unknown":
        return FONTE_SEM_DADOS
    return FONTE_OK


def build_ip_result(ip, abuseipdb_result, virustotal_result, ibm_score,
                    city, country, domain,
                    estado_abuse=FONTE_OK, estado_vt=FONTE_OK, estado_ibm=FONTE_OK):
    # Score None = fonte nao respondeu. Nunca 0, que se confunde com "sem denuncias".
    abuse_confidence = (safe_get(abuseipdb_result, "data", "abuseConfidenceScore", default=0)
                        if estado_abuse == FONTE_OK else None)
    vt_score = (safe_get(virustotal_result, "data", "attributes",
                         "last_analysis_stats", "malicious", default=0)
                if estado_vt == FONTE_OK else None)
    whitelisted = is_whitelisted_abuseipdb(abuseipdb_result) if estado_abuse == FONTE_OK else False

    ibm_numeric = 0
    if estado_ibm == FONTE_OK:
        try:
            ibm_numeric = float(ibm_score)
        except (ValueError, TypeError):
            ibm_numeric = 0

    has_bad_reputation = (abuse_confidence or 0) > 0 or (vt_score or 0) > 0 or ibm_numeric > 1

    fontes_indisponiveis = [nome for nome, estado in (
        ("AbuseIPDB", estado_abuse), ("VirusTotal", estado_vt), ("IBM X-Force", estado_ibm)
    ) if estado in ESTADOS_SEM_RESPOSTA]

    last_reported_at = safe_get(abuseipdb_result, "data", "lastReportedAt")
    if last_reported_at:
        utc_time = datetime.fromisoformat(last_reported_at.replace("Z", "+00:00"))
        last_reported_at = (utc_time - timedelta(hours=3)).strftime("%Y-%m-%d %H:%M:%S")
    else:
        last_reported_at = None

    return {
        "ip": ip,
        "abuse_score": abuse_confidence,
        "vt_score": vt_score,
        "ibm_score": ibm_score,
        "whitelisted": whitelisted,
        "fontes_indisponiveis": fontes_indisponiveis,
        "cota_estourada": FONTE_COTA in (estado_abuse, estado_vt, estado_ibm),
        "estados": {"abuse": estado_abuse, "vt": estado_vt, "ibm": estado_ibm},
        "status": (
            # Deteccao de uma fonte que respondeu ja e conclusao valida, mesmo com
            # outra fora do ar. "Limpo", nao: exige que todas tenham respondido.
            # Whitelist no AbuseIPDB nao anula deteccao das demais bases.
            "whitelisted_bad" if whitelisted and has_bad_reputation else
            "bad" if has_bad_reputation else
            "incompleto" if fontes_indisponiveis else
            "whitelisted" if whitelisted else
            "clean"
        ),
        "domain": domain,
        "country": country,
        "city": city,
        "last_report": last_reported_at,
        "links": {
            "abuse": f"https://www.abuseipdb.com/check/{ip}",
            "vt": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "ibm": f"https://exchange.xforce.ibmcloud.com/ip/{ip}" if ibm_score else None,
        },
    }
