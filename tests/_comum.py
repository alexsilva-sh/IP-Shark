"""Infraestrutura minima dos testes: caminho do src, contagem de falhas e saida legivel.

Sem dependencia externa de propósito -- os testes rodam na mesma venv do build.
"""
import os
import shutil
import sys
import tempfile
from types import SimpleNamespace

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(RAIZ, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

# O registro e o cofre vivem em %LOCALAPPDATA%\IPShark. Sem redirecionar, uma rodada de
# testes despeja avisos de pool e de driver no log real do usuario. Precisa vir antes de
# qualquer import que chame log.obter(), que e quem prende o handler ao arquivo.
_APPDATA = tempfile.mkdtemp(prefix="ipshark-testes-appdata-")
os.environ["LOCALAPPDATA"] = _APPDATA

_falhas = []


def check(condicao, mensagem):
    print(("  OK   " if condicao else "  FALHA") + " | " + mensagem)
    if not condicao:
        _falhas.append(mensagem)


def encerrar():
    shutil.rmtree(_APPDATA, ignore_errors=True)
    if _falhas:
        print(f"\n{len(_falhas)} FALHA(S):")
        for f in _falhas:
            print(f"  - {f}")
        sys.exit(1)
    print("\nTODOS OS TESTES PASSARAM")
    sys.exit(0)


def bloquear_rede(core):
    """Faz qualquer chamada HTTP acidental estourar em vez de passar despercebida.

    Precisa cobrir a Session tambem: `_consultar` nao chama mais `requests.get` direto.
    """
    def _proibido(*_a, **_kw):
        raise AssertionError("chamada de rede dentro do teste")
    core.requests.get = _proibido
    core._sessao = lambda: SimpleNamespace(get=_proibido)
