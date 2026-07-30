"""Modal de escolha das fontes consultadas na aba."""
import tkinter as tk
from tkinter import messagebox

from i18n import t
from ui import fontes as catalogo
from ui import tema
from ui.widgets import Botao, Chip


class DialogoFontes(tk.Toplevel):
    def __init__(self, master, aba, selecionadas, ao_confirmar):
        super().__init__(master)
        self.aba = aba
        self.ao_confirmar = ao_confirmar
        self.vars = {}
        self.chips = []

        self.title(t("src_title"))
        self.configure(bg=tema.FUNDO)
        self.resizable(False, False)
        self.transient(master)

        corpo = tk.Frame(self, bg=tema.FUNDO, padx=tema.E5, pady=tema.E4)
        corpo.pack(fill="both", expand=True)

        titulo = tk.Label(corpo, text=t("src_title"), bg=tema.FUNDO, fg=tema.TEXTO,
                          font=tema.fonte("titulo"), anchor="w")
        titulo.pack(anchor="w")
        tk.Label(corpo, text=t("src_intro"), bg=tema.FUNDO, fg=tema.TEXTO_SECUNDARIO,
                 font=tema.fonte("corpo"), wraplength=440,
                 justify="left").pack(anchor="w", pady=(6, 14))

        for chave, rotulo, tipo in catalogo.CATALOGO[aba]:
            linha = tk.Frame(corpo, bg=tema.FUNDO)
            linha.pack(fill="x", pady=2)
            var = tk.BooleanVar(value=chave in selecionadas)
            self.vars[chave] = var
            chip = Chip(linha, text=t(rotulo), variable=var)
            chip.pack(side="left")
            self.chips.append(chip)
            dica = "src_fast" if tipo == catalogo.API else "src_slow"
            tk.Label(linha, text=t(dica), bg=tema.FUNDO, fg=tema.TEXTO_SECUNDARIO,
                     font=tema.fonte("menor")).pack(side="left", padx=(tema.E2, 0))

        atalhos = tk.Frame(corpo, bg=tema.FUNDO)
        atalhos.pack(fill="x", pady=(14, 0))
        Botao(atalhos, text=t("src_all"), command=self._marcar_todas).pack(side="left")
        Botao(atalhos, text=t("src_only_fast"),
              command=self._marcar_rapidas).pack(side="left", padx=(tema.E2, 0))

        rodape = tk.Frame(corpo, bg=tema.FUNDO)
        rodape.pack(fill="x", pady=(tema.E3, 0))
        Botao(rodape, text=t("src_apply"), tom="primario",
              command=self._aplicar).pack(side="right")
        Botao(rodape, text=t("cfg_cancel"),
              command=self.destroy).pack(side="right", padx=(0, tema.E2))

        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Return>", lambda e: self._aplicar())
        self._centralizar(master)
        self.grab_set()
        self.focus_force()

    def _centralizar(self, master):
        self.update_idletasks()
        largura, altura = self.winfo_width(), self.winfo_height()
        try:
            x = master.winfo_rootx() + (master.winfo_width() - largura) // 2
            y = master.winfo_rooty() + (master.winfo_height() - altura) // 3
        except tk.TclError:
            x = y = 100
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _aplicar_conjunto(self, ativas):
        for chave, var in self.vars.items():
            var.set(chave in ativas)
        for chip in self.chips:
            chip.refresh()

    def _marcar_todas(self):
        self._aplicar_conjunto(catalogo.todas(self.aba))

    def _marcar_rapidas(self):
        self._aplicar_conjunto(catalogo.rapidas(self.aba))

    def selecionadas(self):
        return {chave for chave, var in self.vars.items() if var.get()}

    def _aplicar(self):
        escolhidas = self.selecionadas()
        if not escolhidas:
            messagebox.showwarning(t("src_title"), t("src_none"), parent=self)
            return
        self.ao_confirmar(escolhidas)
        self.destroy()
