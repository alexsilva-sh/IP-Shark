"""Regras que transformam as respostas das fontes em veredito."""
import base64
import ipaddress
import re
import unicodedata
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

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


# Rotulos de 1 a 63 caracteres sem hifen nas pontas, nome inteiro ate 253, e TLD
# alfabetico (ou punycode). O TLD alfabetico e o que descarta "1.2.3.4": IP tem aba propria.
_DOMINIO = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:xn--[a-z0-9-]{2,59}|[a-z]{2,63})$", re.IGNORECASE)


def extrair_dominio(bruto):
    """Descarta esquema, porta e caminho do que o analista colou."""
    alvo = bruto if re.match(r"^\w+://", bruto) else "http://" + bruto
    try:
        endereco = urlparse(alvo)
        return (endereco.netloc or endereco.path).split(":")[0] or bruto
    except ValueError:
        return bruto


def dominio_valido(dominio):
    """O equivalente de is_valid_ip para a aba de dominio.

    Sem isto, lixo colado queima uma vaga do pool de Chrome e cota de API numa consulta
    que ja se sabe que vai falhar.
    """
    return bool(_DOMINIO.fullmatch(dominio or ""))


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


# Nao ha pagina publica por indicador para IP e dominio; o portal e o que da para oferecer.
LINK_MD = "https://my.opswat.com/portal/metadefender-cloud"


def md_detectou(md, estado_md):
    """Contagem de quem acusou, nao de quem mencionou -- por isso decide veredito."""
    return estado_md == FONTE_OK and (safe_get(md, "detectados") or 0) > 0


def _sem_registro(estados):
    """Toda fonte consultada respondeu 'nao conheco este indicador'.

    Nao e limpo: ninguem analisou. O AlienVault fica fora da conta porque pulso e mencao,
    nao analise -- ausencia de pulso nunca foi atestado de nada.
    """
    respostas = [estado for estado in estados if estado is not None]
    return bool(respostas) and all(estado == FONTE_SEM_DADOS for estado in respostas)


def _veredito(malicioso, fontes_indisponiveis, decisivas=()):
    if malicioso:
        return "bad"
    if fontes_indisponiveis:
        return "incompleto"
    return "sem_registros" if _sem_registro(decisivas) else "clean"


def build_ip_result(ip, abuseipdb_result, virustotal_result, ibm_score,
                    city, country, domain,
                    estado_abuse=FONTE_OK, estado_vt=FONTE_OK, estado_ibm=FONTE_OK,
                    md=None, estado_md=None):
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

    has_bad_reputation = ((abuse_confidence or 0) > 0 or (vt_score or 0) > 0 or ibm_numeric > 1
                          or md_detectou(md, estado_md))

    fontes_indisponiveis = _fontes_indisponiveis((
        ("AbuseIPDB", estado_abuse), ("VirusTotal", estado_vt), ("IBM X-Force", estado_ibm),
        ("MetaDefender", estado_md)))

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
        "md": md,
        "fontes_indisponiveis": fontes_indisponiveis,
        "cota_estourada": FONTE_COTA in (estado_abuse, estado_vt, estado_ibm, estado_md),
        "estados": {"abuse": estado_abuse, "vt": estado_vt, "ibm": estado_ibm, "md": estado_md},
        "status": (
            # Deteccao de uma fonte que respondeu ja e conclusao valida, mesmo com
            # outra fora do ar. "Limpo", nao: exige que todas tenham respondido.
            # Whitelist no AbuseIPDB nao anula deteccao das demais bases.
            "whitelisted_bad" if whitelisted and has_bad_reputation else
            "bad" if has_bad_reputation else
            "incompleto" if fontes_indisponiveis else
            "whitelisted" if whitelisted else
            "sem_registros" if _sem_registro((estado_abuse, estado_vt, estado_ibm, estado_md)) else
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
            "md": LINK_MD if estado_md else None,
        },
    }


def build_hash_result(hash_str, virustotal_result, ibm_score, alien, joe_found=False,
                      estado_vt=FONTE_OK, estado_ibm=None, estado_alien=FONTE_OK,
                      md=None, estado_md=None):
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

    # Pulso do OTX fica fora: e mencao da comunidade, nao deteccao (google.com tinha 50).
    malicioso = (
        (vt_score or 0) > 0
        or (estado_ibm == FONTE_OK and str(ibm_score).strip().lower() in ("high", "medium"))
        or md_detectou(md, estado_md)
    )
    fontes = _fontes_indisponiveis((("VirusTotal", estado_vt), ("AlienVault", estado_alien),
                                    ("IBM X-Force", estado_ibm), ("MetaDefender", estado_md)))
    return {
        "hash": hash_str,
        "vt_score": vt_score,
        "ibm_score": ibm_score,
        "alien": alien,
        "md": md,
        "nome_arquivo": nome_arquivo,
        "ultima_analise": ultima_analise,
        "joe_found": joe_found,
        "estados": {"vt": estado_vt, "alien": estado_alien, "ibm": estado_ibm, "md": estado_md},
        "fontes_indisponiveis": fontes,
        "status": _veredito(malicioso, fontes, (estado_vt, estado_ibm, estado_md)),
        "links": {
            "vt": f"https://www.virustotal.com/gui/file/{hash_str}",
            "ibm": f"https://exchange.xforce.ibmcloud.com/malware/{hash_str}",
            "alien": f"https://otx.alienvault.com/indicator/file/{hash_str}",
            "joe": f"https://www.joesandbox.com/analysis/search?q={hash_str}",
            "md": LINK_MD if estado_md else None,
        },
    }


def build_url_result(url, vt_score, ibm_score, alien,
                     estado_vt=FONTE_OK, estado_ibm=None, estado_alien=FONTE_OK,
                     md=None, estado_md=None):
    """Veredito de um dominio. `estado_ibm=None` significa X-Force nao consultado."""
    malicioso = estado_vt == FONTE_OK and (vt_score or 0) > 0
    if estado_ibm == FONTE_OK:
        try:
            # O X-Force devolve nota numerica para dominio e rotulo textual para malware.
            malicioso = malicioso or float(ibm_score) >= 2
        except (ValueError, TypeError):
            malicioso = malicioso or str(ibm_score).strip().lower() in ("high", "medium")
    malicioso = malicioso or md_detectou(md, estado_md)

    fontes = _fontes_indisponiveis((("VirusTotal", estado_vt), ("IBM X-Force", estado_ibm),
                                    ("AlienVault", estado_alien), ("MetaDefender", estado_md)))
    vt_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    return {
        "url": url,
        "vt_score": vt_score,
        "ibm_score": ibm_score,
        "alien": alien,
        "md": md,
        "estados": {"vt": estado_vt, "ibm": estado_ibm, "alien": estado_alien, "md": estado_md},
        "fontes_indisponiveis": fontes,
        "status": _veredito(malicioso, fontes, (estado_vt, estado_ibm, estado_md)),
        "links": {
            "vt": f"https://www.virustotal.com/gui/url/{vt_id}",
            "ibm": f"https://exchange.xforce.ibmcloud.com/url/{url}",
            "alien": f"https://otx.alienvault.com/indicator/url/{url}",
            "md": LINK_MD if estado_md else None,
        },
    }


def _data_da_analise(timestamp):
    if not timestamp:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%d/%m/%Y %H:%M:%S")
