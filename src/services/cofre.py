"""Armazenamento local e criptografado das chaves de API.

As chaves ficam em %LOCALAPPDATA%\\IPShark\\api_keys.dat, cifradas pela DPAPI do
Windows. A chave de criptografia vem das credenciais de logon do usuario, entao o
arquivo so pode ser lido pela mesma conta, na mesma maquina, e o programa nao
precisa guardar senha nenhuma.
"""
import ctypes
import json
import os
import sys
from ctypes import wintypes

import log

_log = log.obter("cofre")

NOME_PASTA = "IPShark"
NOME_ARQUIVO = "api_keys.dat"

# Entropia adicional: um blob cifrado por outro programa da mesma conta nao serve aqui.
_ENTROPIA = b"IPShark::api_keys::v1"

CHAVES = (
    ("ABUSEIPDB_API_KEY", "AbuseIPDB", "https://www.abuseipdb.com/account/api"),
    ("VIRUSTOTAL_API_KEY", "VirusTotal", "https://www.virustotal.com/gui/my-apikey"),
    ("IPINFO_API_KEY", "IPinfo", "https://ipinfo.io/account/token"),
    ("ALIENVAULT_API_KEY", "AlienVault OTX", "https://otx.alienvault.com/api"),
)

_NO_WINDOWS = sys.platform == "win32"
CRYPTPROTECT_UI_FORBIDDEN = 0x01


class _DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_char))]


if _NO_WINDOWS:
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    for _f in (_crypt32.CryptProtectData, _crypt32.CryptUnprotectData):
        _f.restype = wintypes.BOOL
        _f.argtypes = [ctypes.POINTER(_DATA_BLOB), wintypes.LPWSTR,
                       ctypes.POINTER(_DATA_BLOB), ctypes.c_void_p, ctypes.c_void_p,
                       wintypes.DWORD, ctypes.POINTER(_DATA_BLOB)]
    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]


def _para_blob(dados: bytes):
    """Retorna (blob, buffer). O buffer precisa continuar vivo enquanto o blob for usado."""
    buffer = ctypes.create_string_buffer(dados, len(dados))
    return _DATA_BLOB(len(dados), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char))), buffer


def _do_blob(blob: _DATA_BLOB) -> bytes:
    saida = ctypes.create_string_buffer(blob.cbData)
    ctypes.memmove(saida, blob.pbData, blob.cbData)
    return saida.raw


def _chamar_dpapi(funcao, dados: bytes) -> bytes:
    entrada, _b1 = _para_blob(dados)
    entropia, _b2 = _para_blob(_ENTROPIA)
    saida = _DATA_BLOB()
    ok = funcao(ctypes.byref(entrada), None, ctypes.byref(entropia),
                None, None, CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(saida))
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        return _do_blob(saida)
    finally:
        _kernel32.LocalFree(saida.pbData)


def cifrar(dados: bytes) -> bytes:
    return _chamar_dpapi(_crypt32.CryptProtectData, dados)


def decifrar(dados: bytes) -> bytes:
    return _chamar_dpapi(_crypt32.CryptUnprotectData, dados)


def pasta_dados() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, NOME_PASTA)


def caminho_store() -> str:
    return os.path.join(pasta_dados(), NOME_ARQUIVO)


def criptografia_disponivel() -> bool:
    return _NO_WINDOWS


def carregar() -> dict:
    """Le as chaves salvas. Devolve {} se nao houver arquivo ou se ele nao puder ser lido."""
    caminho = caminho_store()
    try:
        with open(caminho, "rb") as f:
            bruto = f.read()
    except OSError:
        return {}
    try:
        conteudo = decifrar(bruto) if criptografia_disponivel() else bruto
        dados = json.loads(conteudo.decode("utf-8"))
    except Exception:
        _log.exception("cofre ilegivel em %s; seguindo sem chaves", caminho)
        return {}
    if not isinstance(dados, dict):
        return {}
    return {k: str(v).strip() for k, v in dados.items() if v}


def salvar(chaves: dict) -> str:
    """Grava as chaves cifradas, descartando campos vazios."""
    limpo = {k: str(v).strip() for k, v in chaves.items() if str(v or "").strip()}
    conteudo = json.dumps(limpo, ensure_ascii=False).encode("utf-8")
    if criptografia_disponivel():
        conteudo = cifrar(conteudo)

    caminho = caminho_store()
    os.makedirs(os.path.dirname(caminho), exist_ok=True)
    temporario = caminho + ".tmp"
    with open(temporario, "wb") as f:
        f.write(conteudo)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temporario, caminho)
    if not criptografia_disponivel():
        try:
            os.chmod(caminho, 0o600)
        except OSError:
            pass
    return caminho


def apagar() -> bool:
    try:
        os.remove(caminho_store())
        return True
    except OSError:
        return False


def caminhos_api_env(base_dir: str) -> list:
    return [os.path.abspath(p) for p in (
        os.path.join(base_dir, "config", "api.env"),
        os.path.join(base_dir, "..", "config", "api.env"),
    )]


def localizar_api_env(base_dir: str):
    return next((p for p in caminhos_api_env(base_dir) if os.path.exists(p)), None)


def ler_api_env(caminho: str) -> dict:
    valores = {}
    try:
        with open(caminho, "r", encoding="utf-8-sig") as f:
            for linha in f:
                linha = linha.strip()
                if not linha or linha.startswith("#") or "=" not in linha:
                    continue
                nome, _, valor = linha.partition("=")
                valor = valor.strip().strip('"').strip("'")
                if valor:
                    valores[nome.strip()] = valor
    except OSError:
        return {}
    return valores


def migrar_se_preciso(base_dir: str) -> bool:
    """Importa o api.env antigo se ainda nao houver chaves salvas.

    Nao apaga o arquivo antigo: quem decide isso e o usuario, pela tela de configuracao.
    """
    if os.path.exists(caminho_store()):
        return False
    antigo = localizar_api_env(base_dir)
    if not antigo:
        return False
    valores = ler_api_env(antigo)
    conhecidas = {nome for nome, _, _ in CHAVES}
    valores = {k: v for k, v in valores.items() if k in conhecidas}
    if not valores:
        return False
    try:
        salvar(valores)
    except Exception:
        _log.exception("falha ao migrar as chaves do api.env")
        return False
    _log.info("chaves migradas de %s para o cofre cifrado", antigo)
    return True
