"""Clientes HTTP das fontes de reputacao e gerencia das chaves de API."""
import base64
import os
import sys
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.paises import traduzir_pais
from services import cofre

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

cofre.migrar_se_preciso(BASE_DIR)

TIMEOUT_HTTP = 15

# Estado de cada fonte consultada. Indisponibilidade nunca pode virar score zero:
# sem isso, rede caida e cota estourada aparecem como "IP limpo".
FONTE_OK = "ok"                      # respondeu com dado utilizavel
FONTE_SEM_DADOS = "sem_dados"        # respondeu, mas nao conhece o indicador
FONTE_SEM_CHAVE = "sem_chave"        # chave ausente ou recusada
FONTE_COTA = "cota"                  # HTTP 429
FONTE_INDISPONIVEL = "indisponivel"  # rede, timeout, 5xx, resposta ilegivel

ESTADOS_SEM_RESPOSTA = (FONTE_SEM_CHAVE, FONTE_COTA, FONTE_INDISPONIVEL)

# 429 fica FORA do status_forcelist de proposito. Cota estourada nao melhora com
# retentativa, e o urllib3 respeita o Retry-After dormindo o que a API mandar -- uma cota
# diaria devolve horas, que congelariam a varredura inteira dentro de uma requisicao.
# Aqui o 429 continua virando FONTE_COTA na hora, e o Retry-After so e lido para avisar.
RECUO = Retry(total=2, backoff_factor=0.5, status_forcelist=(500, 502, 503, 504),
              allowed_methods=("GET",), raise_on_status=False)

# Uma Session por thread, nao uma compartilhada: a Session do requests nao e thread-safe
# (o cookie jar e estado mutavel comum) e a varredura de IP roda com ate 10 workers. Por
# thread, cada worker reaproveita a conexao TCP+TLS com as fontes ao longo de toda a lista,
# que e de onde vem o ganho -- antes cada consulta refazia handshake do zero.
_sessoes = threading.local()


def _sessao():
    sessao = getattr(_sessoes, "atual", None)
    if sessao is None:
        sessao = requests.Session()
        adaptador = HTTPAdapter(max_retries=RECUO)
        sessao.mount("https://", adaptador)
        sessao.mount("http://", adaptador)
        _sessoes.atual = sessao
    return sessao


_esperas_cota = {}
_lock_cota = threading.Lock()


def _registrar_espera(fonte, resposta):
    """Guarda o Retry-After do 429 para o relatorio dizer quando vale repetir.

    O cabecalho tambem admite data HTTP; nessa forma fica sem registro e o aviso sai
    apenas sem a estimativa, que e o comportamento de antes.
    """
    if not fonte:
        return
    try:
        segundos = int(float(resposta.headers.get("Retry-After")))
    except (TypeError, ValueError):
        return
    with _lock_cota:
        _esperas_cota[fonte] = max(0, segundos)


def espera_de_cota(fonte):
    """Segundos ate a cota da fonte renovar, se a API informou. None se nao informou."""
    with _lock_cota:
        return _esperas_cota.get(fonte)

ABUSEIPDB_API_KEY = None
VIRUSTOTAL_API_KEY = None
IPINFO_API_KEY = None
ALIENVAULT_API_KEY = None

_lock_chaves = threading.Lock()
_mtime_store = -1
_chaves_carregadas = False


def reload_api_keys(forcar=False):
    """Recarrega as chaves do cofre, decifrando apenas quando o arquivo muda."""
    global ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, IPINFO_API_KEY, ALIENVAULT_API_KEY
    global _mtime_store, _chaves_carregadas
    try:
        mtime = os.path.getmtime(cofre.caminho_store())
    except OSError:
        mtime = -1
    with _lock_chaves:
        if _chaves_carregadas and not forcar and mtime == _mtime_store:
            return
        dados = cofre.carregar()
        _mtime_store = mtime
        _chaves_carregadas = True
        ABUSEIPDB_API_KEY = dados.get("ABUSEIPDB_API_KEY") or None
        VIRUSTOTAL_API_KEY = dados.get("VIRUSTOTAL_API_KEY") or None
        IPINFO_API_KEY = dados.get("IPINFO_API_KEY") or None
        ALIENVAULT_API_KEY = dados.get("ALIENVAULT_API_KEY") or None


def carregar_chaves_salvas():
    return cofre.carregar()


def salvar_chaves(chaves):
    caminho = cofre.salvar(chaves)
    reload_api_keys(forcar=True)
    return caminho


reload_api_keys()


def safe_get(d, *keys, default=None):
    for key in keys:
        if isinstance(d, dict) and key in d:
            d = d[key]
        else:
            return default
    return d


def _consultar(url, fonte=None, **kwargs):
    """GET com timeout que classifica a resposta. Devolve (json, estado)."""
    kwargs.setdefault("timeout", TIMEOUT_HTTP)
    try:
        resposta = _sessao().get(url, **kwargs)
    except requests.exceptions.RequestException:
        return None, FONTE_INDISPONIVEL
    if resposta.status_code == 429:
        _registrar_espera(fonte, resposta)
        return None, FONTE_COTA
    if resposta.status_code == 404:
        return None, FONTE_SEM_DADOS
    if resposta.status_code in (401, 403):
        return None, FONTE_SEM_CHAVE
    if resposta.status_code != 200:
        return None, FONTE_INDISPONIVEL
    try:
        return resposta.json(), FONTE_OK
    except ValueError:
        return None, FONTE_INDISPONIVEL


def check_ip_abuseipdb(ip):
    reload_api_keys()
    if not ABUSEIPDB_API_KEY:
        return None, FONTE_SEM_CHAVE
    return _consultar("https://api.abuseipdb.com/api/v2/check", fonte="AbuseIPDB",
                      headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
                      params={"ipAddress": ip, "maxAgeInDays": 90})


def check_ip_virustotal(ip):
    reload_api_keys()
    if not VIRUSTOTAL_API_KEY:
        return None, FONTE_SEM_CHAVE
    return _consultar(f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                      fonte="VirusTotal", headers={"x-apikey": VIRUSTOTAL_API_KEY})


def check_hash_virustotal(hash_str):
    reload_api_keys()
    if not VIRUSTOTAL_API_KEY:
        return None, FONTE_SEM_CHAVE
    return _consultar(f"https://www.virustotal.com/api/v3/files/{hash_str}",
                      fonte="VirusTotal", headers={"x-apikey": VIRUSTOTAL_API_KEY})


def check_url_virustotal(url):
    reload_api_keys()
    if not VIRUSTOTAL_API_KEY:
        return {"score": None, "not_found": False}, FONTE_SEM_CHAVE
    vt_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    dados, estado = _consultar(f"https://www.virustotal.com/api/v3/urls/{vt_id}",
                               fonte="VirusTotal",
                               headers={"x-apikey": VIRUSTOTAL_API_KEY,
                                        "Accept": "application/json"})
    if estado == FONTE_SEM_DADOS:
        return {"score": None, "not_found": True}, FONTE_SEM_DADOS
    if estado != FONTE_OK:
        return {"score": None, "not_found": False}, estado
    score = safe_get(dados, "data", "attributes",
                     "last_analysis_stats", "malicious", default=0)
    return {"score": score, "not_found": False}, FONTE_OK


def _alienvault(tipo, indicador, link):
    """Consulta o OTX. Devolve (contagem_de_pulsos, link, estado)."""
    reload_api_keys()
    if not ALIENVAULT_API_KEY:
        return None, link, FONTE_SEM_CHAVE
    dados, estado = _consultar(
        f"https://otx.alienvault.com/api/v1/indicators/{tipo}/{indicador}/general",
        fonte="AlienVault",
        headers={"X-OTX-API-KEY": ALIENVAULT_API_KEY, "Accept": "application/json"})
    if estado == FONTE_SEM_DADOS:
        return "0", link, FONTE_OK   # indicador ausente do OTX significa zero pulsos
    if estado != FONTE_OK:
        return None, link, estado
    return str(safe_get(dados, "pulse_info", "count", default=0)), link, FONTE_OK


def check_hash_alienvault(hash_str):
    return _alienvault("file", hash_str, f"https://otx.alienvault.com/indicator/file/{hash_str}")


def check_url_alienvault(url):
    return _alienvault("url", url, f"https://otx.alienvault.com/indicator/url/{url}")


def get_location(ip):
    reload_api_keys()
    dados, estado = _consultar(f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}")
    if estado != FONTE_OK:
        return "N/A", "N/A"
    return dados.get("city", "N/A"), traduzir_pais(dados.get("country", "N/A"))
