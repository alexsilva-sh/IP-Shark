"""Janela de "nova versao disponivel"."""
import re
import tkinter as tk
import webbrowser
from tkinter import scrolledtext, ttk

from i18n import t
from services.atualizacao import versao_mais_recente
from ui import tema
from ui.widgets import Botao

RELEASES = "https://github.com/alexsilva-sh/IP-Shark/releases"


def limpar_markdown(texto):
    """Converte as notas de release do GitHub em (linha, estilo) legiveis fora do navegador."""
    linhas = []
    dentro_de_codigo = False
    for bruta in (texto or "").splitlines():
        linha = bruta.rstrip()
        if linha.strip().startswith("```"):
            dentro_de_codigo = not dentro_de_codigo
            continue
        if dentro_de_codigo:
            if linha.strip():
                linhas.append((linha.strip(), "texto"))
            continue

        linha = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", linha)
        linha = linha.replace("**", "").replace("`", "")
        linha = re.sub(r"^\s*>\s?", "", linha)

        cabecalho = re.match(r"^\s*#{1,6}\s*(.+)$", linha)
        if cabecalho:
            linhas.append((cabecalho.group(1).strip(), "titulo"))
            continue

        item = re.match(r"^\s*[-*+]\s+(.+)$", linha)
        if item:
            linhas.append((item.group(1).strip(), "item"))
            continue

        if linha.strip():
            # Junta linhas seguidas num paragrafo so, deixando a quebra a cargo do widget.
            if linhas and linhas[-1][1] == "texto" and linhas[-1][0]:
                linhas[-1] = (f"{linhas[-1][0]} {linha.strip()}", "texto")
            else:
                linhas.append((linha.strip(), "texto"))
        elif linhas and linhas[-1][0]:
            linhas.append(("", "texto"))
    while linhas and not linhas[-1][0]:
        linhas.pop()
    return linhas


def mostrar_janela_atualizacao(versao, novidades):
    janela = tk.Toplevel()
    janela.title(t("update_available"))
    janela.configure(bg=tema.FUNDO)
    janela.minsize(520, 360)

    tk.Label(janela, text=t("new_version_available").format(version=versao), bg=tema.FUNDO,
             fg="white", font=("Segoe UI", 11, "bold")).pack(pady=(14, 2), padx=16, anchor="w")
    tk.Label(janela, text=t("whats_new"), bg=tema.FUNDO, fg=tema.TEXTO_SECUNDARIO,
             font=("Segoe UI", 9)).pack(pady=(0, 8), padx=16, anchor="w")

    caixa = scrolledtext.ScrolledText(janela, wrap=tk.WORD, bg="#141414", fg=tema.TEXTO,
                                      font=("Segoe UI", 10), relief=tk.FLAT, height=13,
                                      width=62, padx=12, pady=10, borderwidth=0)
    caixa.pack(fill=tk.BOTH, expand=True, padx=16)
    caixa.tag_configure("titulo", foreground=tema.LINK, font=("Segoe UI", 10, "bold"),
                        spacing1=10, spacing3=4)
    caixa.tag_configure("item", lmargin1=14, lmargin2=28, spacing3=3)
    caixa.tag_configure("texto", spacing3=3)

    conteudo = limpar_markdown(novidades) or [(t("cannot_load_release_notes"), "texto")]
    for linha, estilo in conteudo:
        prefixo = "• " if estilo == "item" else ""
        caixa.insert(tk.END, f"{prefixo}{linha}\n", estilo)
    caixa.config(state=tk.DISABLED)

    rodape = tk.Frame(janela, bg=tema.FUNDO)
    rodape.pack(fill="x", padx=16, pady=12)
    Botao(rodape, text=t("close"),
               command=janela.destroy).pack(side="right")
    Botao(rodape, text=t("download_github"), tom="primario",
               command=lambda: webbrowser.open(RELEASES)).pack(side="right", padx=(0, 8))
    janela.bind("<Escape>", lambda e: janela.destroy())


def verificar_em_segundo_plano(root, versao_atual):
    versao, novidades = versao_mais_recente(versao_atual)
    if not versao:
        return
    try:
        root.after(0, lambda: mostrar_janela_atualizacao(versao, novidades))
    except tk.TclError:
        pass   # janela fechada antes de a verificacao terminar
