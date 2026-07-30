"""Idioma da aplicacao: carga dos locales, traducao e notificacao de troca."""
import importlib.util
import os
import sys

_IDIOMAS = {}
_atual = "pt"
_ouvintes = []


def _carregar(nome):
    if getattr(sys, "frozen", False):
        caminho = os.path.join(sys._MEIPASS, "locales", f"{nome}.py")
    else:
        caminho = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales", f"{nome}.py")
    spec = importlib.util.spec_from_file_location(nome, caminho)
    modulo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modulo)
    return modulo.STRINGS


_IDIOMAS["pt"] = _carregar("pt_BR")
_IDIOMAS["en"] = _carregar("en_US")


def t(chave):
    return _IDIOMAS[_atual].get(chave, chave)


def plural(chave, itens, separador=", "):
    """Escolhe a variante _one ou _many conforme a quantidade e preenche {lista}."""
    texto = t(f"{chave}_one" if len(itens) == 1 else f"{chave}_many")
    if "{lista}" in texto:
        texto = texto.format(lista=separador.join(sorted(itens)))
    return texto


def idioma_atual():
    return _atual


def definir_idioma(lang):
    global _atual
    _atual = lang
    os.environ["APP_LANG"] = lang   # lido por core.paises para traduzir o nome do pais
    for ouvinte in _ouvintes:
        ouvinte()


def ao_trocar_idioma(callback):
    _ouvintes.append(callback)
