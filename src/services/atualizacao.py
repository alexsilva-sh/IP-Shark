"""Verificacao de nova versao no GitHub."""
import re

import requests

import log

REPO = "alexsilva-sh/IP-Shark"

_log = log.obter("atualizacao")


def _numeros(tag):
    """('v4.10' -> (4, 10)). Trecho nao numerico e ignorado, e o que sobra ordena."""
    return tuple(int(p) for p in re.findall(r"\d+", str(tag or "")))


def e_mais_nova(candidata, atual):
    """A tag publicada e posterior a que esta rodando?

    Comparar por diferenca marcava como "atualizacao disponivel" qualquer tag distinta --
    inclusive uma **mais antiga** que a publicada, que e o que acontece em todo build local
    feito antes do release.
    """
    numeros_candidata, numeros_atual = _numeros(candidata), _numeros(atual)
    if not numeros_candidata or not numeros_atual:
        # Sem numero de que se agarrar, so a diferenca resta -- e ela nunca afirma
        # regressao, apenas avisa que ha algo diferente publicado.
        return bool(candidata) and candidata != atual
    return numeros_candidata > numeros_atual


def versao_mais_recente(versao_atual):
    """Devolve (tag, notas) quando ha versao nova; (None, None) caso contrario."""
    try:
        resposta = requests.get(f"https://api.github.com/repos/{REPO}/releases/latest", timeout=5)
        if resposta.status_code != 200:
            return None, None
        dados = resposta.json()
        if e_mais_nova(dados.get("tag_name"), versao_atual):
            return dados["tag_name"], dados.get("body", "")
    except Exception as e:
        # Sem internet e o caso comum e nao merece alarme: o app sobe igual.
        _log.debug("verificacao de versao falhou: %s", type(e).__name__)
    return None, None
