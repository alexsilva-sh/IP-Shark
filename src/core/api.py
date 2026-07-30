"""Clientes HTTP das fontes de reputacao e gerencia das chaves de API."""
import base64
import os
import sys
import threading
import time

import requests
from requests.adapters import HTTPAdapter

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

# Retentativa por fonte e por indicador. So para indisponibilidade: cota, chave recusada
# e "sem registros" nao melhoram insistindo, e o Retry-After de cota diaria vem em horas.
TENTATIVAS_FONTE = 3
PAUSA_RETENTATIVA = 0.8   # segundos; cresce a cada tentativa


def _sem_cancelamento():
    return False


_cancelado = _sem_cancelamento


def definir_cancelamento(callback):
    """Registra como saber que a varredura foi cancelada -- ninguem insiste depois disso."""
    global _cancelado
    _cancelado = callback or _sem_cancelamento


def tentativas():
    """Rende o numero de cada tentativa, pausando so entre uma e a proxima."""
    for numero in range(1, TENTATIVAS_FONTE + 1):
        if numero > 1:
            time.sleep(PAUSA_RETENTATIVA * (numero - 1))
        yield numero


# Uma Session por thread, nao uma compartilhada: a Session do requests nao e thread-safe
# (o cookie jar e estado mutavel comum) e a varredura de IP roda com ate 10 workers. Por
# thread, cada worker reaproveita a conexao TCP+TLS com as fontes ao longo de toda a lista,
# que e de onde vem o ganho -- antes cada consulta refazia handshake do zero.
_sessoes = threading.local()


def _sessao():
    sessao = getattr(_sessoes, "atual", None)
    if sessao is None:
        sessao = requests.Session()
        # Sem retentativa do urllib3: multiplicaria com a de `_consultar`.
        adaptador = HTTPAdapter(max_retries=0)
        sessao.mount("https://", adaptador)
        sessao.mount("http://", adaptador)
        _sessoes.atual = sessao
    return sessao


URL_ABUSEIPDB = "https://api.abuseipdb.com/api/v2/check"
URL_VT_IP = "https://www.virustotal.com/api/v3/ip_addresses/{}"
URL_VT_ARQUIVO = "https://www.virustotal.com/api/v3/files/{}"
URL_VT_URL = "https://www.virustotal.com/api/v3/urls/{}"
URL_OTX = "https://otx.alienvault.com/api/v1/indicators/{}/{}/general"
URL_IPINFO = "https://ipinfo.io/{}/json"

# O que cada API conta sobre a propria cota: {fonte: {"restante": int, "espera": int}}.
_cotas = {}
_lock_cota = threading.Lock()


def _inteiro(bruto):
    try:
        return max(0, int(float(bruto)))
    except (TypeError, ValueError):
        return None


def _registrar_cota(fonte, resposta):
    """Le o que a resposta contou sobre a cota. Nunca inventa numero.

    `Retry-After` tambem admite data HTTP; nessa forma nao vira estimativa, e o aviso sai
    sem o prazo em vez de sair com um valor chutado.
    """
    if not fonte:
        return
    novo = {}
    restante = _inteiro(resposta.headers.get("X-RateLimit-Remaining"))
    if restante is not None:
        novo["restante"] = restante
    if resposta.status_code == 429:
        espera = _inteiro(resposta.headers.get("Retry-After"))
        if espera is not None:
            novo["espera"] = espera
        novo["restante"] = 0
    if novo:
        with _lock_cota:
            _cotas.setdefault(fonte, {}).update(novo)


def espera_de_cota(fonte):
    """Segundos ate a cota da fonte renovar, se a API informou. None se nao informou."""
    with _lock_cota:
        return _cotas.get(fonte, {}).get("espera")


def cotas_restantes():
    """{fonte: consultas restantes}, so das APIs que informam o cabecalho."""
    with _lock_cota:
        return {fonte: dados["restante"] for fonte, dados in _cotas.items()
                if dados.get("restante") is not None}

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
    """GET com timeout que classifica a resposta. Devolve (json, estado).

    Indisponibilidade e retentada ate TENTATIVAS_FONTE vezes; o resto sai na primeira.
    """
    kwargs.setdefault("timeout", TIMEOUT_HTTP)
    for _ in tentativas():
        dados, estado = _uma_tentativa(url, fonte, **kwargs)
        if estado != FONTE_INDISPONIVEL or _cancelado():
            break
    return dados, estado


def _uma_tentativa(url, fonte, **kwargs):
    try:
        resposta = _sessao().get(url, **kwargs)
    except requests.exceptions.RequestException:
        return None, FONTE_INDISPONIVEL
    _registrar_cota(fonte, resposta)
    if resposta.status_code == 429:
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
    return _consultar(URL_ABUSEIPDB, fonte="AbuseIPDB",
                      headers={"Accept": "application/json", "Key": ABUSEIPDB_API_KEY},
                      params={"ipAddress": ip, "maxAgeInDays": 90})


def check_ip_virustotal(ip):
    reload_api_keys()
    if not VIRUSTOTAL_API_KEY:
        return None, FONTE_SEM_CHAVE
    return _consultar(URL_VT_IP.format(ip),
                      fonte="VirusTotal", headers={"x-apikey": VIRUSTOTAL_API_KEY})


def check_hash_virustotal(hash_str):
    reload_api_keys()
    if not VIRUSTOTAL_API_KEY:
        return None, FONTE_SEM_CHAVE
    return _consultar(URL_VT_ARQUIVO.format(hash_str),
                      fonte="VirusTotal", headers={"x-apikey": VIRUSTOTAL_API_KEY})


def check_url_virustotal(url):
    reload_api_keys()
    if not VIRUSTOTAL_API_KEY:
        return {"score": None, "not_found": False}, FONTE_SEM_CHAVE
    vt_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    dados, estado = _consultar(URL_VT_URL.format(vt_id),
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
        URL_OTX.format(tipo, indicador),
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
    dados, estado = _consultar(URL_IPINFO.format(ip), fonte="IPinfo",
                               params={"token": IPINFO_API_KEY})
    if estado != FONTE_OK:
        return "N/A", "N/A"
    return dados.get("city", "N/A"), traduzir_pais(dados.get("country", "N/A"))


# 8.8.8.8 e publico, estavel e nao e dado de cliente: serve so para provar que a chave
# passa e a fonte responde.
IP_TESTE = "8.8.8.8"


def _sondas(chaves):
    """(nome_da_chave, fonte, url, cabecalhos, params) de uma consulta barata por fonte."""
    return (
        ("ABUSEIPDB_API_KEY", "AbuseIPDB", URL_ABUSEIPDB,
         {"Accept": "application/json", "Key": chaves.get("ABUSEIPDB_API_KEY")},
         {"ipAddress": IP_TESTE, "maxAgeInDays": 1}),
        ("VIRUSTOTAL_API_KEY", "VirusTotal", URL_VT_IP.format(IP_TESTE),
         {"x-apikey": chaves.get("VIRUSTOTAL_API_KEY")}, None),
        ("IPINFO_API_KEY", "IPinfo", URL_IPINFO.format(IP_TESTE),
         None, {"token": chaves.get("IPINFO_API_KEY")}),
        ("ALIENVAULT_API_KEY", "AlienVault", URL_OTX.format("IPv4", IP_TESTE),
         {"X-OTX-API-KEY": chaves.get("ALIENVAULT_API_KEY"), "Accept": "application/json"}, None),
    )


def testar_fontes(chaves=None):
    """Testa cada chave contra a API de verdade. Devolve {nome_da_chave: estado}.

    Aceita chaves ainda nao salvas para a tela de configuracao poder testar o que esta
    digitado. Chave em branco nao e testada e nao aparece no resultado -- so o que o
    usuario preencheu. Cada teste gasta uma requisicao da cota da fonte.
    """
    chaves = carregar_chaves_salvas() if chaves is None else chaves
    resultados = {}
    for nome, fonte, url, cabecalhos, params in _sondas(chaves):
        if not (chaves.get(nome) or "").strip():
            continue
        _dados, estado = _consultar(url, fonte=fonte, headers=cabecalhos, params=params)
        # 404 aqui prova o que interessa: a chave passou e a fonte respondeu.
        resultados[nome] = FONTE_OK if estado == FONTE_SEM_DADOS else estado
    return resultados
