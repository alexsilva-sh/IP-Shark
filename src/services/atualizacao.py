"""Verificacao de nova versao no GitHub."""
import requests

import log

REPO = "alexsilva-sh/IP-Shark"

_log = log.obter("atualizacao")


def versao_mais_recente(versao_atual):
    """Devolve (tag, notas) quando ha versao nova; (None, None) caso contrario."""
    try:
        resposta = requests.get(f"https://api.github.com/repos/{REPO}/releases/latest", timeout=5)
        if resposta.status_code != 200:
            return None, None
        dados = resposta.json()
        if dados["tag_name"] != versao_atual:
            return dados["tag_name"], dados.get("body", "")
    except Exception as e:
        # Sem internet e o caso comum e nao merece alarme: o app sobe igual.
        _log.debug("verificacao de versao falhou: %s", type(e).__name__)
    return None, None
