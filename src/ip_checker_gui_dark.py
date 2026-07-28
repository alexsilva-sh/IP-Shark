"""Ponto de entrada do IP Shark: monta a janela e liga os componentes.

O nome do arquivo e mantido porque e o script apontado por ipshark.spec.
"""
import os
import sys
import tkinter as tk
from threading import Thread
from tkinter import ttk

import i18n
from app import VERSAO, IPCheckerApp
from i18n import t
from ui import tema
from ui.dialogo_config import ConfigAPIDialog
from ui.janela_atualizacao import verificar_em_segundo_plano

TITULO = f"IP Shark {VERSAO} - by @alexsilva.sh in Github"


def _caminho_icone():
    if getattr(sys, "frozen", False):
        return os.path.join(sys._MEIPASS, "assets", "shark.ico")
    return os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                        "..", "assets", "shark.ico"))


def main():
    root = tk.Tk()
    tema.configurar_estilos(ttk.Style())
    root.minsize(900, 600)
    root.state("zoomed")
    root.title(TITULO)

    barra = tk.Frame(root, bg=tema.FUNDO)
    barra.pack(pady=(5, 0))
    botoes_idioma = {
        "pt": ttk.Button(barra, text="🇧🇷 PT", style="Nav.TButton",
                         command=lambda: i18n.definir_idioma("pt")),
        "en": ttk.Button(barra, text="🇺🇸 EN", style="Nav.TButton",
                         command=lambda: i18n.definir_idioma("en")),
    }
    for botao in botoes_idioma.values():
        botao.pack(side="left", padx=5)

    app = IPCheckerApp(root)

    botao_config = ttk.Button(barra, text=t("btn_config_api"), style="Secondary.TButton",
                              command=lambda: ConfigAPIDialog(root))
    botao_config.pack(side="left", padx=(15, 5))
    app._register_i18n(botao_config, "btn_config_api")

    def destacar_idioma():
        for lang, botao in botoes_idioma.items():
            botao.config(style="NavActive.TButton" if lang == i18n.idioma_atual() else "Nav.TButton")

    i18n.ao_trocar_idioma(app.refresh_language)
    i18n.ao_trocar_idioma(destacar_idioma)
    destacar_idioma()

    icone = _caminho_icone()
    if os.path.exists(icone):
        root.iconbitmap(icone)

    root.protocol("WM_DELETE_WINDOW", app.on_close)
    Thread(target=lambda: verificar_em_segundo_plano(root, VERSAO), daemon=True).start()
    root.mainloop()


if __name__ == "__main__":
    main()
