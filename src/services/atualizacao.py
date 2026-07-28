"""Verificacao de nova versao no GitHub."""
import requests

REPO = "alexsilva-sh/IP-Shark"


def versao_mais_recente(versao_atual):
    """Devolve (tag, notas) quando ha versao nova; (None, None) caso contrario."""
    try:
        resposta = requests.get(f"https://api.github.com/repos/{REPO}/releases/latest", timeout=5)
        if resposta.status_code != 200:
            return None, None
        dados = resposta.json()
        if dados["tag_name"] != versao_atual:
            return dados["tag_name"], dados.get("body", "")
    except Exception:
        pass
    return None, None
