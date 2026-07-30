"""Preferencias de tela, guardadas entre sessoes.

Guarda apenas escolha de aparencia e idioma. **Nao guarda indicador de cliente** -- por isso
pode ir para disco, ao contrario do historico da sessao e do registro em arquivo, que evitam
gravar IP, hash e dominio (ver `src/log.py`).

Perder o arquivo, ou ele vir corrompido, nao pode impedir o app de abrir: qualquer falha cai
no padrao embutido.
"""
import json
import os

import log

_log = log.obter("preferencias")

NOME_PASTA = "IPShark"
NOME_ARQUIVO = "preferencias.json"

PADRAO = {"tema": "escuro", "escala": 0, "idioma": "pt"}


def pasta_dados() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, NOME_PASTA)


def caminho() -> str:
    return os.path.join(pasta_dados(), NOME_ARQUIVO)


def carregar() -> dict:
    """Preferencias salvas sobre o padrao. Chave desconhecida ou tipo errado e ignorada."""
    valores = dict(PADRAO)
    try:
        with open(caminho(), encoding="utf-8") as arquivo:
            salvas = json.load(arquivo)
    except FileNotFoundError:
        return valores
    except (OSError, ValueError) as erro:
        _log.warning("preferencias ilegiveis, usando o padrao: %s", type(erro).__name__)
        return valores
    if not isinstance(salvas, dict):
        return valores
    for chave, padrao in PADRAO.items():
        valor = salvas.get(chave)
        if isinstance(valor, type(padrao)) and not isinstance(valor, bool):
            valores[chave] = valor
    return valores


def salvar(**mudancas) -> bool:
    """Mescla com o que ja esta salvo. Disco somente-leitura nao derruba o app."""
    valores = carregar()
    valores.update({c: v for c, v in mudancas.items() if c in PADRAO})
    try:
        os.makedirs(pasta_dados(), exist_ok=True)
        with open(caminho(), "w", encoding="utf-8") as arquivo:
            json.dump(valores, arquivo, indent=2)
    except OSError as erro:
        _log.warning("nao foi possivel salvar as preferencias: %s", type(erro).__name__)
        return False
    return True
