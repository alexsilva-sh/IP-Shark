"""Regras que transformam as respostas das fontes em veredito."""
import base64
import ipaddress
import unicodedata
from datetime import datetime, timedelta, timezone

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


def _fontes_indisponiveis(pares):
    return [nome for nome, estado in pares if estado in ESTADOS_SEM_RESPOSTA]


def _veredito(malicioso, fontes_indisponiveis):
    return "bad" if malicioso else ("incompleto" if fontes_indisponiveis else "clean")


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

    fontes_indisponiveis = _fontes_indisponiveis((
        ("AbuseIPDB", estado_abuse), ("VirusTotal", estado_vt), ("IBM X-Force", estado_ibm)))

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


def build_hash_result(hash_str, virustotal_result, ibm_score, alien_score, joe_found=False,
                      estado_vt=FONTE_OK, estado_ibm=None, estado_alien=FONTE_OK):
    """Veredito de um hash. `estado_ibm=None` significa X-Force nao consultado."""
    atributos = safe_get(virustotal_result, "data", "attributes")
    if estado_vt != FONTE_OK or not isinstance(atributos, dict):
        vt_score, nome_arquivo, ultima_analise = None, None, None
        if estado_vt == FONTE_OK:
            estado_vt = FONTE_SEM_DADOS   # respondeu 200, mas sem o bloco de atributos
    else:
        vt_score = safe_get(atributos, "last_analysis_stats", "malicious", default=0)
        nome_arquivo = safe_get(atributos, "meaningful_name")
        ultima_analise = _data_da_analise(safe_get(atributos, "last_analysis_date"))

    malicioso = (
        (vt_score or 0) > 0
        or (estado_ibm == FONTE_OK and str(ibm_score).strip().lower() in ("high", "medium"))
        or (estado_alien == FONTE_OK and alien_score not in ("0", None))
    )
    fontes = _fontes_indisponiveis((("VirusTotal", estado_vt), ("AlienVault", estado_alien),
                                    ("IBM X-Force", estado_ibm)))
    return {
        "hash": hash_str,
        "vt_score": vt_score,
        "ibm_score": ibm_score,
        "alien_score": alien_score,
        "nome_arquivo": nome_arquivo,
        "ultima_analise": ultima_analise,
        "joe_found": joe_found,
        "estados": {"vt": estado_vt, "alien": estado_alien, "ibm": estado_ibm},
        "fontes_indisponiveis": fontes,
        "status": _veredito(malicioso, fontes),
        "links": {
            "vt": f"https://www.virustotal.com/gui/file/{hash_str}",
            "ibm": f"https://exchange.xforce.ibmcloud.com/malware/{hash_str}",
            "alien": f"https://otx.alienvault.com/indicator/file/{hash_str}",
            "joe": f"https://www.joesandbox.com/analysis/search?q={hash_str}",
        },
    }


def build_url_result(url, vt_score, ibm_score, alien_score,
                     estado_vt=FONTE_OK, estado_ibm=None, estado_alien=FONTE_OK):
    """Veredito de um dominio. `estado_ibm=None` significa X-Force nao consultado."""
    malicioso = estado_vt == FONTE_OK and (vt_score or 0) > 0
    if estado_ibm == FONTE_OK:
        try:
            # O X-Force devolve nota numerica para dominio e rotulo textual para malware.
            malicioso = malicioso or float(ibm_score) >= 2
        except (ValueError, TypeError):
            malicioso = malicioso or str(ibm_score).strip().lower() in ("high", "medium")
    if estado_alien == FONTE_OK and str(alien_score).strip() not in ("0", "-", ""):
        malicioso = True

    fontes = _fontes_indisponiveis((("VirusTotal", estado_vt), ("IBM X-Force", estado_ibm),
                                    ("AlienVault", estado_alien)))
    vt_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return {
        "url": url,
        "vt_score": vt_score,
        "ibm_score": ibm_score,
        "alien_score": alien_score,
        "estados": {"vt": estado_vt, "ibm": estado_ibm, "alien": estado_alien},
        "fontes_indisponiveis": fontes,
        "status": _veredito(malicioso, fontes),
        "links": {
            "vt": f"https://www.virustotal.com/gui/url/{vt_id}",
            "ibm": f"https://exchange.xforce.ibmcloud.com/url/{url}",
            "alien": f"https://otx.alienvault.com/indicator/url/{url}",
        },
    }


def _data_da_analise(timestamp):
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
