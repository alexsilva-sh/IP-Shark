"""Aparencia: paleta, grade de espacamento e escala tipografica.

Fonte unica de verdade. Cor literal e tamanho de fonte solto no meio da tela quebram o tema
claro e o ajuste de fonte, porque o Tk nao cascateia estilo -- o que foi escrito na criacao
do widget fica la para sempre.

Trocar de tema repinta a arvore por substituicao de cor: como as duas paletas tem as mesmas
chaves, o mapa cor_antiga -> cor_nova cobre qualquer widget ja criado sem precisar registrar
um por um. O que a repintura nao alcanca -- item de canvas, tag de texto, tag de Treeview --
se inscreve em `ao_trocar`.
"""
import tkinter as tk
from tkinter import font as tkfont

# Grade de 4 px: todo padx/pady sai daqui, e nao de numeros soltos (secao 3.2).
E1, E2, E3, E4, E5, E6 = 4, 8, 12, 16, 20, 24

PALETAS = {
    "escuro": {
        "FUNDO": "#16181c",          # cinza-escuro no lugar do preto puro: menos fadiga
        "FUNDO_PAINEL": "#1b1e24",
        "FUNDO_CAMPO": "#23262d",
        "FUNDO_TABELA": "#101216",
        "FUNDO_AVISO": "#3a2a12",
        "BORDA": "#2c3038",
        "TEXTO": "#e6e8eb",
        "TEXTO_SECUNDARIO": "#9aa0a6",
        "LINK": "#4da3ff",
        "ACENTO": "#007acc",
        "ACENTO_ATIVO": "#1e90ff",
        "BOTAO": "#2a2f38",
        "BOTAO_ATIVO": "#363c47",
        "PERIGO": "#a83232",
        "PERIGO_ATIVO": "#8a2020",
        "SELECAO": "#0a3d5c",
        "LIMPO": "#35d07f",          # verde menos neon que o #00ff99 original
        "REVISAR": "#ffb020",
        "MALICIOSO": "#ff5c5c",
        "INDISPONIVEL": "#9aa0a6",   # igual ao secundario nas duas paletas, de proposito
        "LIGADO": "#2e9e5b",
        "DESLIGADO": "#3a3f48",
    },
    "claro": {
        "FUNDO": "#f4f5f7",
        "FUNDO_PAINEL": "#e9ebef",
        "FUNDO_CAMPO": "#ffffff",
        "FUNDO_TABELA": "#ffffff",
        "FUNDO_AVISO": "#fff3d4",
        "BORDA": "#d3d7de",
        "TEXTO": "#1c1f24",
        "TEXTO_SECUNDARIO": "#5b6169",
        "LINK": "#0b64c8",
        "ACENTO": "#0a66c2",
        "ACENTO_ATIVO": "#0b78e0",
        "BOTAO": "#e0e3e8",
        "BOTAO_ATIVO": "#cfd4dc",
        "PERIGO": "#c0392b",
        "PERIGO_ATIVO": "#a3271b",
        "SELECAO": "#cfe4f7",
        "LIMPO": "#1e7b34",
        "REVISAR": "#8a5a00",
        "MALICIOSO": "#c0261f",
        "INDISPONIVEL": "#5b6169",
        "LIGADO": "#1e7b34",
        "DESLIGADO": "#b6bcc5",
    },
}

TEMA_PADRAO = "escuro"
_atual = TEMA_PADRAO
_style = None
_ouvintes = []


def _publicar(nome):
    """Deixa as cores da paleta como atributos do modulo: tema.FUNDO, tema.TEXTO, ..."""
    globals().update(PALETAS[nome])
    globals()["_atual"] = nome


_publicar(TEMA_PADRAO)


def nome_atual():
    return _atual


# ---------- tipografia ----------

BASE = 10
ESCALA_MIN, ESCALA_MAX = -2, 6

# (familia, ajuste sobre BASE, peso, sublinhado)
_DEFINICOES = {
    "menor": ("Segoe UI", -2, "normal", False),
    "corpo": ("Segoe UI", -1, "normal", False),
    "forte": ("Segoe UI", -1, "bold", False),
    "titulo": ("Segoe UI", 1, "bold", False),
    "link": ("Segoe UI", -2, "normal", True),
    "mono": ("Consolas", 0, "normal", False),
    "mono_forte": ("Consolas", 0, "bold", False),
}

_escala = 0
_fontes = {}


def fonte(nome):
    """Fonte nomeada do Tk: mudar o tamanho aqui reflete ao vivo em tudo que a usa."""
    if nome not in _fontes:
        familia, ajuste, peso, sublinhado = _DEFINICOES[nome]
        _fontes[nome] = tkfont.Font(family=familia, size=BASE + ajuste + _escala,
                                    weight=peso, underline=sublinhado)
    return _fontes[nome]


def escala_atual():
    return _escala


def fator_escala():
    """Quanto o texto cresceu. Largura fixa em pixel (coluna de tabela) precisa acompanhar,
    senao aumentar a fonte passa a cortar o conteudo."""
    return (BASE + _escala) / BASE


def definir_escala(valor):
    """Ajusta o corpo de texto inteiro. Devolve a escala aplicada, ja limitada."""
    global _escala
    _escala = max(ESCALA_MIN, min(ESCALA_MAX, valor))
    for nome, objeto in _fontes.items():
        objeto.configure(size=BASE + _DEFINICOES[nome][1] + _escala)
    if _style is not None:
        configurar_estilos(_style)
    for ouvinte in _ouvintes:
        ouvinte()
    return _escala


# ---------- troca de tema ----------

def ao_trocar(callback):
    _ouvintes.append(callback)


_OPCOES_COR = ("background", "foreground", "insertbackground", "selectbackground",
               "selectforeground", "highlightbackground", "highlightcolor",
               "activebackground", "activeforeground", "disabledforeground", "troughcolor")


def _repintar(widget, traducao):
    for opcao in _OPCOES_COR:
        try:
            atual = str(widget.cget(opcao)).lower()
        except (tk.TclError, AttributeError, TypeError):
            continue
        novo = traducao.get(atual)
        if novo:
            try:
                widget.configure(**{opcao: novo})
            except tk.TclError:
                pass
    for filho in widget.winfo_children():
        _repintar(filho, traducao)


def aplicar(root, nome):
    """Troca a paleta e repinta o que ja esta na tela."""
    if nome not in PALETAS or nome == _atual:
        return _atual
    anterior = PALETAS[_atual]
    traducao = {anterior[chave].lower(): PALETAS[nome][chave] for chave in anterior}
    _publicar(nome)
    if _style is not None:
        configurar_estilos(_style)
    _repintar(root, traducao)
    for ouvinte in _ouvintes:
        ouvinte()
    return _atual


def alternar(root):
    return aplicar(root, "claro" if _atual == "escuro" else "escuro")


# ---------- estilos ttk ----------

def configurar_estilos(style):
    global _style
    _style = style
    style.theme_use("clam")   # trocar de tema descarta o que ja foi configurado
    p = PALETAS[_atual]
    corpo, forte, titulo, mono = fonte("corpo"), fonte("forte"), fonte("titulo"), fonte("mono")

    style.configure("Nav.TButton", background=p["FUNDO_PAINEL"], foreground=p["TEXTO"],
                    font=forte, padding=(E3, E2), anchor="w", borderwidth=0, relief="flat")
    style.map("Nav.TButton", background=[("active", p["BOTAO_ATIVO"])])
    style.configure("NavActive.TButton", background=p["ACENTO"], foreground="#ffffff",
                    font=forte, padding=(E3, E2), anchor="w", borderwidth=0, relief="flat")
    style.map("NavActive.TButton", background=[("active", p["ACENTO_ATIVO"])])

    style.configure("Secondary.TButton", background=p["BOTAO"], foreground=p["TEXTO"],
                    font=corpo, padding=(E3, E1 + 1), borderwidth=0)
    style.map("Secondary.TButton",
              background=[("disabled", p["FUNDO_PAINEL"]), ("active", p["BOTAO_ATIVO"])],
              foreground=[("disabled", p["TEXTO_SECUNDARIO"])])
    style.configure("Danger.TButton", background=p["PERIGO"], foreground="#ffffff",
                    font=forte, padding=(E3, E1 + 1), borderwidth=0)
    style.map("Danger.TButton",
              background=[("disabled", p["FUNDO_PAINEL"]), ("active", p["PERIGO_ATIVO"])],
              foreground=[("disabled", p["TEXTO_SECUNDARIO"])])
    style.configure("Primary.TButton", background=p["ACENTO"], foreground="#ffffff",
                    font=forte, padding=(E4, E2), borderwidth=0)
    style.map("Primary.TButton",
              background=[("disabled", p["FUNDO_PAINEL"]), ("active", p["ACENTO_ATIVO"])],
              foreground=[("disabled", p["TEXTO_SECUNDARIO"])])

    style.configure("Custom.TEntry", fieldbackground=p["FUNDO_CAMPO"], foreground=p["TEXTO"],
                    insertcolor=p["TEXTO"], borderwidth=0, padding=E2)
    style.configure("Status.TLabel", background=p["FUNDO"], foreground=p["LIMPO"], font=corpo)
    style.configure("Title.TLabel", background=p["FUNDO"], foreground=p["TEXTO"], font=titulo)

    style.configure("Result.Treeview", background=p["FUNDO_TABELA"],
                    fieldbackground=p["FUNDO_TABELA"], foreground=p["TEXTO"], font=mono,
                    rowheight=mono.metrics("linespace") + E2, borderwidth=0)
    style.map("Result.Treeview", background=[("selected", p["SELECAO"])],
              foreground=[("selected", p["TEXTO"])])
    style.configure("Result.Treeview.Heading", background=p["FUNDO_PAINEL"],
                    foreground=p["TEXTO"], font=forte, relief="flat", padding=(E2, E1 + 1))
    style.map("Result.Treeview.Heading", background=[("active", p["BOTAO_ATIVO"])])
    style.configure("Scan.Horizontal.TProgressbar", troughcolor=p["FUNDO_CAMPO"],
                    bordercolor=p["FUNDO_CAMPO"], background=p["ACENTO"],
                    lightcolor=p["ACENTO"], darkcolor=p["ACENTO"], thickness=E2)
