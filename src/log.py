"""Registro em arquivo dos erros que a tela nao mostra.

Num executavel `console=False` o `print()` nao vai para lugar nenhum: sem isto, falha de
driver e de cofre somem sem deixar rastro. O nivel sai de `IPSHARK_LOG` (padrao INFO).

**Nao registra IP, hash nem dominio de cliente.** O arquivo fica em disco por dias, e o
indicador ja aparece na linha do resultado e no relatorio -- repetir aqui criaria exposicao
nova, do mesmo tipo que motivou tirar as chaves do `api.env`. Por isso varios registros
gravam so o tipo da excecao, sem a mensagem, que em Selenium e requests costuma trazer a URL
consultada junto.
"""
import logging
import os
from logging.handlers import RotatingFileHandler

# Mesma pasta do cofre, sem importar services.cofre: la o import de log.py fecharia um ciclo.
NOME_PASTA = "IPShark"
NOME_ARQUIVO = "ipshark.log"
LIMITE_BYTES = 512 * 1024   # com BACKUPS, o registro nao passa de ~1,5 MB
BACKUPS = 2
NIVEIS = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")

_configurado = False


def pasta_dados() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, NOME_PASTA)


def caminho_log() -> str:
    return os.path.join(pasta_dados(), NOME_ARQUIVO)


def configurar():
    """Idempotente. Disco sem permissao de escrita nao pode derrubar o app."""
    global _configurado
    if _configurado:
        return
    _configurado = True
    raiz = logging.getLogger("ipshark")
    nivel = os.environ.get("IPSHARK_LOG", "INFO").upper()
    raiz.setLevel(nivel if nivel in NIVEIS else "INFO")
    raiz.propagate = False
    try:
        os.makedirs(pasta_dados(), exist_ok=True)
        manipulador = RotatingFileHandler(caminho_log(), maxBytes=LIMITE_BYTES,
                                          backupCount=BACKUPS, encoding="utf-8")
    except OSError:
        return
    manipulador.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)s | %(message)s", datefmt="%Y-%m-%d %H:%M:%S"))
    raiz.addHandler(manipulador)


def obter(nome):
    configurar()
    return logging.getLogger("ipshark").getChild(nome)
