"""Infraestrutura minima dos testes: caminho do src, contagem de falhas e saida legivel.

Sem dependencia externa de propósito -- os testes rodam na mesma venv do build.
"""
import os
import sys

RAIZ = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(RAIZ, "src")
if SRC not in sys.path:
    sys.path.insert(0, SRC)

_falhas = []


def check(condicao, mensagem):
    print(("  OK   " if condicao else "  FALHA") + " | " + mensagem)
    if not condicao:
        _falhas.append(mensagem)


def encerrar():
    if _falhas:
        print(f"\n{len(_falhas)} FALHA(S):")
        for f in _falhas:
            print(f"  - {f}")
        sys.exit(1)
    print("\nTODOS OS TESTES PASSARAM")
    sys.exit(0)


def bloquear_rede(core):
    """Faz qualquer chamada HTTP acidental estourar em vez de passar despercebida."""
    def _proibido(*_a, **_kw):
        raise AssertionError("chamada de rede dentro do teste")
    core.requests.get = _proibido
