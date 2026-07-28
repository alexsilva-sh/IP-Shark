"""Widgets proprios: interruptor animado, entrada com contador e tabela de resultados."""
import tkinter as tk
import webbrowser
from tkinter import scrolledtext, ttk

from i18n import t
from ui import tema
from ui.apresentacao import VERDICT_TAGS


class ToggleSwitch(tk.Frame):
    def __init__(self, master, text="", variable=None, on_bg="#00c853", off_bg="#3a3a3a",
                 width=48, height=26, state="normal", **kw):
        super().__init__(master, bg=master["bg"], **kw)
        self.var = variable or tk.BooleanVar(value=False)
        self.state = state
        self.on_bg = on_bg
        self.off_bg = off_bg
        self.canvas = tk.Canvas(self, width=width, height=height, highlightthickness=0, bg=master["bg"])
        self.canvas.pack(side="left")
        self.label = tk.Label(self, text=text, fg="white", bg=master["bg"])
        self.label.pack(side="left", padx=(6, 0))
        r = height // 2 - 2
        self.x = 2
        self.l = self.canvas.create_oval(2, 2, height - 2, height - 2, fill=off_bg, outline="")
        self.m = self.canvas.create_rectangle(height // 2, 2, width - height // 2, height - 2, fill=off_bg, outline="")
        self.r = self.canvas.create_oval(width - height + 2, 2, width - 2, height - 2, fill=off_bg, outline="")
        self.shadow = self.canvas.create_oval(3, 3, 3 + 2 * r, 3 + 2 * r, fill="#000", outline="", stipple="gray25")
        self.knob = self.canvas.create_oval(2, 2, 2 + 2 * r, 2 + 2 * r, fill="#fff", outline="")
        self.canvas.bind("<Button-1>", self._toggle)
        self.label.bind("<Button-1>", self._toggle)
        self.canvas.bind("<Enter>", lambda e: self._hover(True))
        self.canvas.bind("<Leave>", lambda e: self._hover(False))
        self._update()
        if state == "disabled":
            self._disable()

    def _set_track(self, cor):
        for parte in (self.l, self.m, self.r):
            self.canvas.itemconfig(parte, fill=cor)

    def _toggle(self, _=None):
        if self.state == "disabled":
            return
        self.var.set(not self.var.get())
        self._update()

    def _update(self):
        w = int(self.canvas["width"])
        h = int(self.canvas["height"])
        r = h // 2 - 2
        alvo = w - 2 - 2 * r if self.var.get() else 2
        self._set_track(self.on_bg if self.var.get() else self.off_bg)
        for i in range(8):
            nx = self.x + (alvo - self.x) * (i + 1) / 8
            self.canvas.after(i * 10, lambda x=nx: self._move(x))
        self.x = alvo

    def _move(self, x):
        r = int(self.canvas["height"]) // 2 - 2
        self.canvas.coords(self.knob, x, 2, x + 2 * r, 2 + 2 * r)
        self.canvas.coords(self.shadow, x + 1, 3, x + 1 + 2 * r, 3 + 2 * r)

    def _hover(self, ligado):
        if self.state != "disabled" and self.var.get():
            self._set_track("#2ee96b" if ligado else self.on_bg)

    def _disable(self):
        self.label.config(fg="#666")
        self._set_track("#2a2a2a")
        self.canvas.itemconfig(self.knob, fill="#888")
        self.canvas.itemconfig(self.shadow, fill="")

    def set_state(self, s):
        self.state = s
        self._disable() if s == "disabled" else self._update()

    def set_text(self, texto):
        self.label.config(text=texto)


class MultilineInput(tk.Frame):
    """Campo de varias linhas com contador ao vivo do conteudo colado."""

    def __init__(self, master, contador, altura=4):
        super().__init__(master, bg=master["bg"])
        self._contador = contador
        self.texto = tk.Text(self, height=altura, bg=tema.FUNDO_CAMPO, fg="white",
                             insertbackground="white", font=("Consolas", 10), relief=tk.FLAT,
                             wrap=tk.WORD, padx=8, pady=6, undo=True)
        self.texto.pack(fill="x")
        self.resumo = tk.Label(self, bg=master["bg"], fg=tema.TEXTO_SECUNDARIO,
                               font=("Segoe UI", 9), anchor="w")
        self.resumo.pack(fill="x", pady=(4, 0))
        self.texto.bind("<KeyRelease>", self.refresh)
        self.texto.bind("<<Paste>>", lambda e: self.after(20, self.refresh))
        self.refresh()

    def get_text(self):
        return self.texto.get("1.0", tk.END)

    def focus_set(self):
        self.texto.focus_set()

    def refresh(self, _=None):
        self.resumo.config(text=self._contador(self.get_text()))


class ResultTable(tk.Frame):
    """Tabela ordenavel de resultados com painel de detalhe da linha selecionada."""

    def __init__(self, master, colunas, altura_detalhe=9):
        super().__init__(master, bg=master["bg"])
        self.colunas = colunas
        self._textos = {}
        self._ordem = []
        self._preambulo = ""
        self._ordenacao = (None, False)

        painel = tk.PanedWindow(self, orient="vertical", bg=tema.FUNDO, sashwidth=6,
                                sashrelief="flat", bd=0, sashpad=0)
        painel.pack(fill="both", expand=True)

        quadro_tabela = tk.Frame(painel, bg=tema.FUNDO)
        ids = [c[0] for c in colunas]
        self.tree = ttk.Treeview(quadro_tabela, columns=ids[1:], show="tree headings",
                                 style="Result.Treeview", selectmode="browse")
        barra = ttk.Scrollbar(quadro_tabela, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=barra.set)
        barra.pack(side="right", fill="y")
        self.tree.pack(side="left", fill="both", expand=True)

        self.tree.column("#0", width=colunas[0][2], minwidth=140, anchor="w", stretch=True)
        self.tree.heading("#0", anchor="w", command=lambda: self._ordenar("#0"))
        for cid, _chave, largura, ancora in colunas[1:]:
            self.tree.column(cid, width=largura, minwidth=60, anchor=ancora, stretch=False)
            self.tree.heading(cid, anchor=ancora, command=lambda c=cid: self._ordenar(c))

        self.tree.tag_configure("bad", foreground=tema.MALICIOSO)
        self.tree.tag_configure("review", foreground=tema.REVISAR)
        self.tree.tag_configure("clean", foreground=tema.LIMPO)
        self.tree.tag_configure("unknown", foreground=tema.INDISPONIVEL)
        self.tree.bind("<<TreeviewSelect>>", self._ao_selecionar)

        quadro_detalhe = tk.Frame(painel, bg=tema.FUNDO)
        self.detalhe = scrolledtext.ScrolledText(quadro_detalhe, wrap=tk.WORD, bg=tema.FUNDO_TABELA,
                                                 fg=tema.TEXTO, font=("Consolas", 10),
                                                 relief=tk.FLAT, height=altura_detalhe,
                                                 padx=10, pady=8)
        self.detalhe.pack(fill="both", expand=True)
        self.detalhe.tag_configure("cabecalho", font=("Consolas", 10, "bold"))
        self.detalhe.tag_configure("dica", foreground="#6b6b6b")
        self.detalhe.tag_configure("preambulo", foreground=tema.REVISAR)
        self.detalhe.config(state=tk.DISABLED)

        painel.add(quadro_tabela, stretch="always", minsize=140)
        painel.add(quadro_detalhe, stretch="never", minsize=90)

        self.refresh_language()
        self.clear()

    def refresh_language(self):
        self.tree.heading("#0", text=t(self.colunas[0][1]), anchor="w")
        for cid, chave, _largura, ancora in self.colunas[1:]:
            self.tree.heading(cid, text=t(chave), anchor=ancora)
        if not self._ordem:
            self.clear()

    def clear(self):
        self.tree.delete(*self.tree.get_children(""))
        self._textos.clear()
        self._ordem.clear()
        self._preambulo = ""
        self._ordenacao = (None, False)
        self._escrever([(t("detail_hint"), "dica")])

    def is_empty(self):
        return not self._ordem

    def add(self, iid, valores, texto, status, parent=""):
        self.tree.insert(parent, "end", iid=iid, text=str(valores[0]),
                         values=[str(v) for v in valores[1:]],
                         tags=(VERDICT_TAGS.get(status, "clean"),), open=True)
        self._textos[iid] = texto
        self._ordem.append(iid)
        self.tree.see(iid)
        if len(self._ordem) == 1:
            self.tree.selection_set(iid)

    def set_preamble(self, texto):
        self._preambulo = texto or ""
        if self._preambulo:
            self._escrever([(self._preambulo, "preambulo")])

    def report(self):
        partes = [self._preambulo] if self._preambulo else []
        partes += [self._textos[iid] for iid in self._ordem if iid in self._textos]
        return "\n\n".join(p.strip("\n") for p in partes) + "\n"

    def _ao_selecionar(self, _=None):
        selecao = self.tree.selection()
        if selecao and selecao[0] in self._textos:
            self._escrever_relatorio(self._textos[selecao[0]])

    def _escrever(self, blocos):
        self.detalhe.config(state=tk.NORMAL)
        self.detalhe.delete("1.0", tk.END)
        for texto, tag in blocos:
            self.detalhe.insert(tk.END, texto + "\n", tag)
        self.detalhe.config(state=tk.DISABLED)

    def _escrever_relatorio(self, texto):
        self.detalhe.config(state=tk.NORMAL)
        self.detalhe.delete("1.0", tk.END)
        for i, linha in enumerate(texto.split("\n")):
            url = linha.strip()[2:].strip() if linha.strip().startswith("- ") else ""
            if url.startswith("http"):
                tag = f"link{i}"
                self.detalhe.tag_configure(tag, foreground=tema.LINK, underline=True)
                self.detalhe.tag_bind(tag, "<Button-1>", lambda e, u=url: webbrowser.open(u))
                self.detalhe.tag_bind(tag, "<Enter>", lambda e: self.detalhe.config(cursor="hand2"))
                self.detalhe.tag_bind(tag, "<Leave>", lambda e: self.detalhe.config(cursor=""))
                self.detalhe.insert(tk.END, linha + "\n", tag)
            else:
                self.detalhe.insert(tk.END, linha + "\n", "cabecalho" if i == 0 else "")
        self.detalhe.config(state=tk.DISABLED)

    def _ordenar(self, coluna):
        atual, invertido = self._ordenacao
        invertido = not invertido if atual == coluna else False
        pares = [(self._chave_ordem(self._valor(iid, coluna)), iid)
                 for iid in self.tree.get_children("")]
        pares.sort(reverse=invertido)
        for pos, (_chave, iid) in enumerate(pares):
            self.tree.move(iid, "", pos)
        self._ordenacao = (coluna, invertido)

    def _valor(self, iid, coluna):
        return self.tree.item(iid, "text") if coluna == "#0" else self.tree.set(iid, coluna)

    @staticmethod
    def _chave_ordem(valor):
        try:
            return (0, float(str(valor).strip().rstrip("%")), "")
        except ValueError:
            return (1, 0.0, str(valor).lower())
