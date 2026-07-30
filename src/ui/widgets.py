"""Widgets proprios: interruptor animado, entrada com contador e tabela de resultados."""
import tkinter as tk
import webbrowser
from tkinter import scrolledtext, ttk

from i18n import t
from ui import tema
from ui.apresentacao import VERDICT_TAGS


def _retangulo_arredondado(canvas, x0, y0, x1, y1, raio, **kw):
    """Canto arredondado no Tk sai de um poligono suavizado: nao existe borda-raio."""
    pontos = [x0 + raio, y0, x1 - raio, y0, x1, y0, x1, y0 + raio,
              x1, y1 - raio, x1, y1, x1 - raio, y1, x0 + raio, y1,
              x0, y1, x0, y1 - raio, x0, y0 + raio, x0, y0]
    return canvas.create_polygon(pontos, smooth=True, **kw)


class _Pilula(tk.Canvas):
    """Desenho comum do chip e do botao: pilula arredondada que segue tema e escala.

    Existe como base porque canto arredondado no Tk sai de poligono suavizado desenhado num
    canvas, e um Canvas nao aceita `config(text=...)` nem `state` -- os dois precisam ser
    interceptados. Fazer isso duas vezes daria duas implementacoes para divergir.
    """

    RAIO = 11
    ALTURA_EXTRA = 12
    LARGURA_EXTRA = 30

    def __init__(self, master, text="", state="normal", fonte="corpo",
                 largura_total=False, alinhamento="center"):
        super().__init__(master, bg=master["bg"], highlightthickness=0, bd=0,
                         cursor="hand2" if state == "normal" else "")
        self._texto = text
        self._nome_fonte = fonte
        self._largura_total = largura_total
        self._alinhamento = alinhamento
        self._tom = None
        self.state = state
        self._sob_cursor = False
        self.bind("<Button-1>", self._clicar)
        self.bind("<Enter>", lambda _e: self._realcar(True))
        self.bind("<Leave>", lambda _e: self._realcar(False))
        if largura_total:
            self.bind("<Configure>", lambda _e: self._desenhar())
        tema.ao_trocar(self._desenhar)

    def configure(self, **kw):
        """Intercepta text/state/tom: um Canvas nao entende nenhum dos tres."""
        redesenhar = False
        if "text" in kw:
            self._texto = kw.pop("text")
            redesenhar = True
        if "state" in kw:
            self.state = kw.pop("state")
            super().configure(cursor="hand2" if self.state == "normal" else "")
            redesenhar = True
        if "tom" in kw:
            self._tom = kw.pop("tom")
            redesenhar = True
        if kw:
            super().configure(**kw)
        if redesenhar:
            self._desenhar()

    config = configure

    def cget(self, chave):
        """`state` e opcao nativa do Canvas, mas a nossa e outra coisa.

        Nao repassamos ao canvas de proposito: com state=disabled ele passa a desenhar os
        itens com `disabledfill`, que e vazio, e a pilula desapareceria. Quem le
        `botao["state"]` quer saber se o botao esta clicavel, e e isso que devolvemos.
        """
        return self.state if chave == "state" else super().cget(chave)

    __getitem__ = cget

    def set_text(self, texto):
        self.configure(text=texto)

    def set_state(self, estado):
        self.configure(state=estado)

    def _realcar(self, dentro):
        self._sob_cursor = dentro
        self._desenhar()

    def _rotulo(self):
        return self._texto

    def _cores(self):
        raise NotImplementedError

    def _clicar(self, _=None):
        raise NotImplementedError

    def _desenhar(self):
        try:
            fonte = tema.fonte(self._nome_fonte)
            rotulo = self._rotulo()
            minima = fonte.measure(rotulo) + self.LARGURA_EXTRA
            altura = fonte.metrics("linespace") + self.ALTURA_EXTRA
            if self._largura_total:
                largura = max(self.winfo_width(), minima)
                super().configure(height=altura)
            else:
                largura = minima
                super().configure(width=largura, height=altura)
            super().configure(bg=self.master["bg"])
            self.delete("all")
            fundo, borda, cor = self._cores()
            _retangulo_arredondado(self, 1, 1, largura - 1, altura - 1, self.RAIO,
                                   fill=fundo, outline=borda, width=1)
            if self._alinhamento == "w":
                self.create_text(self.RAIO + tema.E1, altura / 2, text=rotulo, fill=cor,
                                 font=fonte, anchor="w")
            else:
                self.create_text(largura / 2, altura / 2, text=rotulo, fill=cor, font=fonte)
        except tk.TclError:
            pass   # widget ja destruido


class Chip(_Pilula):
    """Pilula de opcao: preenchida com o acento quando ativa, so contornada quando nao.

    Substitui o interruptor animado. Ocupa menos altura, que e o que importa em tela
    pequena, e o estado fica legivel pelo simbolo alem da cor (secao 3.3).
    """

    def __init__(self, master, text="", variable=None, state="normal", ao_mudar=None):
        self.var = variable or tk.BooleanVar(value=False)
        self._ao_mudar = ao_mudar
        super().__init__(master, text=text, state=state)
        self._desenhar()

    def _rotulo(self):
        return ("✓ " if self.var.get() else "") + self._texto

    def _clicar(self, _=None):
        if self.state == "disabled":
            return
        self.var.set(not self.var.get())
        self._desenhar()
        if self._ao_mudar:
            self._ao_mudar()

    # Mantido: as abas chamam _alternar direto nos testes e no callback da pre-analise.
    _alternar = _clicar

    def _cores(self):
        if self.state == "disabled":
            return tema.FUNDO_PAINEL, tema.BORDA, tema.TEXTO_SECUNDARIO
        if self.var.get():
            fundo = tema.ACENTO_ATIVO if self._sob_cursor else tema.ACENTO
            return fundo, fundo, "#ffffff"
        borda = tema.TEXTO_SECUNDARIO if self._sob_cursor else tema.BORDA
        return self.master["bg"], borda, tema.TEXTO


class Botao(_Pilula):
    """Botao de acao no mesmo desenho do chip, para a tela toda falar a mesma lingua.

    `tom` escolhe o peso visual: primario para a acao principal, secundario para as de
    apoio, perigo para o que interrompe ou apaga, nav para a barra lateral.
    """

    TONS = ("primario", "secundario", "perigo", "nav", "nav_ativo")

    def __init__(self, master, text="", command=None, tom="secundario", state="normal"):
        self._comando = command
        lateral = tom.startswith("nav")
        super().__init__(master, text=text, state=state,
                         fonte="corpo" if tom == "secundario" else "forte",
                         largura_total=lateral, alinhamento="w" if lateral else "center")
        self._tom = tom
        self._desenhar()

    def configure(self, **kw):
        if "command" in kw:
            self._comando = kw.pop("command")
        super().configure(**kw)

    config = configure

    def _clicar(self, _=None):
        if self.state != "disabled" and self._comando:
            self._comando()

    def invoke(self):
        self._clicar()

    def _cores(self):
        if self.state == "disabled":
            return tema.FUNDO_PAINEL, tema.FUNDO_PAINEL, tema.TEXTO_SECUNDARIO
        if self._tom in ("primario", "nav_ativo"):
            fundo = tema.ACENTO_ATIVO if self._sob_cursor else tema.ACENTO
            return fundo, fundo, "#ffffff"
        if self._tom == "perigo":
            fundo = tema.PERIGO_ATIVO if self._sob_cursor else tema.PERIGO
            return fundo, fundo, "#ffffff"
        if self._tom == "nav":
            fundo = tema.BOTAO_ATIVO if self._sob_cursor else self.master["bg"]
            return fundo, fundo, tema.TEXTO
        fundo = tema.BOTAO_ATIVO if self._sob_cursor else tema.BOTAO
        return fundo, tema.BORDA, tema.TEXTO


class RotuloSecao(tk.Label):
    """Titulo de grupo em caixa alta que sobrevive a troca de idioma."""

    def __init__(self, master, chave):
        super().__init__(master, text=t(chave).upper(), bg=master["bg"],
                         fg=tema.TEXTO_SECUNDARIO, font=tema.fonte("menor"), anchor="w")

    def configure(self, **kw):
        if "text" in kw:
            kw["text"] = kw["text"].upper()
        super().configure(**kw)

    config = configure


class Cartao(tk.Frame):
    """Superficie de secao: fundo elevado, borda de 1 px e titulo opcional.

    A borda sai de um Frame externo com 1 px de padding -- o Tk nao tem borda colorida
    de espessura fixa que respeite o tema.
    """

    def __init__(self, master, chave_titulo=None, registrar=None):
        super().__init__(master, bg=tema.BORDA)
        interno = tk.Frame(self, bg=tema.FUNDO_PAINEL)
        interno.pack(fill="both", expand=True, padx=1, pady=1)
        self.titulo = None
        if chave_titulo:
            self.titulo = tk.Label(interno, text=t(chave_titulo).upper(), bg=tema.FUNDO_PAINEL,
                                   fg=tema.TEXTO_SECUNDARIO, font=tema.fonte("menor"),
                                   anchor="w")
            self.titulo.pack(fill="x", padx=tema.E4, pady=(tema.E3, tema.E2))
            if registrar:
                registrar(self, chave_titulo)
        self.corpo = tk.Frame(interno, bg=tema.FUNDO_PAINEL)
        self.corpo.pack(fill="both", expand=True, padx=tema.E4,
                        pady=(0, tema.E4) if chave_titulo else tema.E4)

    def configure(self, **kw):
        """Titulo de secao em caixa alta: intercepta para o i18n nao perder o estilo."""
        if "text" in kw and self.titulo is not None:
            self.titulo.config(text=kw.pop("text").upper())
        if kw:
            super().configure(**kw)

    config = configure


class MultilineInput(tk.Frame):
    """Campo de varias linhas com contador ao vivo e altura que segue o conteudo.

    Comeca baixo em vez de reservar quatro linhas vazias, e cresce ate ALTURA_MAX conforme
    o analista cola. Passando disso, rola.
    """

    ALTURA_MIN = 2
    # Teto pensado para 720 px de altura: acima disso a entrada come o espaco da tabela e
    # do painel de detalhe, que importam mais depois que a varredura comeca.
    ALTURA_MAX = 8

    def __init__(self, master, contador, altura=None):
        super().__init__(master, bg=master["bg"])
        self._contador = contador
        self.texto = tk.Text(self, height=altura or self.ALTURA_MIN,
                             bg=tema.FUNDO_CAMPO, fg=tema.TEXTO,
                             insertbackground=tema.TEXTO, font=tema.fonte("mono"),
                             relief=tk.FLAT, wrap=tk.WORD, padx=tema.E2, pady=tema.E2,
                             undo=True)
        self.texto.pack(fill="x")
        self.resumo = tk.Label(self, bg=master["bg"], fg=tema.TEXTO_SECUNDARIO,
                               font=tema.fonte("corpo"), anchor="w")
        self.resumo.pack(fill="x", pady=(tema.E1, 0))
        self.texto.bind("<KeyRelease>", self.refresh)
        self.texto.bind("<<Paste>>", lambda e: self.after(20, self.refresh))
        self.refresh()

    def get_text(self):
        return self.texto.get("1.0", tk.END)

    def focus_set(self):
        self.texto.focus_set()

    def refresh(self, _=None):
        self.resumo.config(text=self._contador(self.get_text()))
        self._ajustar_altura()

    def _ajustar_altura(self):
        """Conta linhas logicas: a entrada e um indicador por linha, nao texto corrido."""
        try:
            linhas = int(self.texto.index("end-1c").split(".")[0])
            desejada = max(self.ALTURA_MIN, min(self.ALTURA_MAX, linhas))
            if desejada != int(self.texto.cget("height")):
                self.texto.config(height=desejada)
        except (tk.TclError, ValueError):
            pass   # widget destruido no meio de um callback atrasado


class ResultTable(tk.Frame):
    """Tabela ordenavel de resultados com painel de detalhe da linha selecionada."""

    def __init__(self, master, colunas, altura_detalhe=9):
        super().__init__(master, bg=master["bg"])
        self.colunas = colunas
        self._textos = {}
        self._ordem = []
        self._preambulo = ""
        self._avisos = ""
        self._ordenacao = (None, False)

        painel = tk.PanedWindow(self, orient="vertical", bg=tema.FUNDO, sashwidth=tema.E2,
                                sashrelief="flat", bd=0, sashpad=0)
        painel.pack(fill="both", expand=True)

        quadro_tabela = tk.Frame(painel, bg=tema.FUNDO)
        ids = [c[0] for c in colunas]
        self.tree = ttk.Treeview(quadro_tabela, columns=ids[1:], show="tree headings",
                                 style="Result.Treeview", selectmode="browse")
        barra = ttk.Scrollbar(quadro_tabela, orient="vertical", command=self.tree.yview)
        # Barra horizontal: em tela menor a soma das colunas passa da largura da janela, e
        # sem ela as ultimas colunas ficavam inalcancaveis, nao so apertadas.
        barra_h = ttk.Scrollbar(quadro_tabela, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=barra.set, xscrollcommand=barra_h.set)
        barra.pack(side="right", fill="y")
        barra_h.pack(side="bottom", fill="x")
        self.tree.pack(side="left", fill="both", expand=True)

        self.tree.column("#0", width=colunas[0][2], minwidth=120, anchor="w", stretch=False)
        self.tree.heading("#0", anchor="w", command=lambda: self._ordenar("#0"))
        for indice, (cid, _chave, largura, ancora) in enumerate(colunas[1:]):
            # A ultima coluna estica para absorver a sobra; as demais mantem a largura.
            ultima = indice == len(colunas) - 2
            self.tree.column(cid, width=largura, minwidth=60, anchor=ancora, stretch=ultima)
            self.tree.heading(cid, anchor=ancora, command=lambda c=cid: self._ordenar(c))

        self.tree.bind("<<TreeviewSelect>>", self._ao_selecionar)
        self.tree.bind("<Button-1>", self._ao_clicar, add="+")

        quadro_detalhe = tk.Frame(painel, bg=tema.FUNDO)
        self.detalhe = scrolledtext.ScrolledText(quadro_detalhe, wrap=tk.WORD, bg=tema.FUNDO_TABELA,
                                                 fg=tema.TEXTO, font=tema.fonte("mono"),
                                                 relief=tk.FLAT, height=altura_detalhe,
                                                 padx=tema.E3, pady=tema.E2)
        self.detalhe.pack(fill="both", expand=True)
        self.detalhe.config(state=tk.DISABLED)

        # minsize do detalhe garante espaco util em janela baixa: com 90 px ele encolhia
        # para uma linha e o analista perdia os links de vista.
        painel.add(quadro_tabela, stretch="always", minsize=120)
        painel.add(quadro_detalhe, stretch="never", minsize=150)

        self._aplicar_tema()
        tema.ao_trocar(self._aplicar_tema)
        self.refresh_language()
        self.clear()

    def _aplicar_tema(self):
        """Tag de Treeview e de Text guarda a cor por valor: precisa ser refeita na troca."""
        try:
            for tag, chave in (("bad", "MALICIOSO"), ("review", "REVISAR"),
                               ("clean", "LIMPO"), ("unknown", "INDISPONIVEL")):
                self.tree.tag_configure(tag, foreground=getattr(tema, chave))
            self.detalhe.config(font=tema.fonte("mono"))
            self.detalhe.tag_configure("cabecalho", font=tema.fonte("mono_forte"))
            self.detalhe.tag_configure("dica", foreground=tema.TEXTO_SECUNDARIO)
            self.detalhe.tag_configure("preambulo", foreground=tema.TEXTO)
            self.detalhe.tag_configure("aviso", foreground=tema.REVISAR)
            self.detalhe.tag_configure("aviso_titulo", foreground=tema.REVISAR,
                                       font=tema.fonte("mono_forte"))
            fator = tema.fator_escala()
            self.tree.column("#0", width=int(self.colunas[0][2] * fator))
            for cid, _chave, largura, _ancora in self.colunas[1:]:
                self.tree.column(cid, width=int(largura * fator))
            for filho in self.winfo_children():
                filho.config(bg=tema.FUNDO)
        except tk.TclError:
            pass   # tabela ja destruida

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
        self._avisos = ""
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

    def set_preamble(self, texto, avisos=""):
        """`texto` abre o relatorio copiado; `avisos` fica so na tela.

        O analista cola o resultado direto para o cliente: recado operacional nao viaja.
        """
        self._preambulo = texto or ""
        self._avisos = avisos or ""
        if self._blocos_resumo():
            self.mostrar_resumo()

    def _blocos_resumo(self):
        blocos = []
        if self._avisos:
            blocos.append((t("warnings_not_copied"), "aviso_titulo"))
            blocos.append((self._avisos, "aviso"))
        if self._preambulo:
            blocos.append((self._preambulo, "preambulo"))
        return blocos

    def mostrar_resumo(self):
        """Volta o painel para os avisos e o resumo, sem nenhuma linha selecionada."""
        selecao = self.tree.selection()
        if selecao:
            self.tree.selection_remove(*selecao)
        self._escrever(self._blocos_resumo() or [(t("detail_hint"), "dica")])

    def _ao_clicar(self, evento):
        # "nothing" e a area vazia abaixo das linhas; no cabecalho o clique so ordena.
        if self.tree.identify_region(evento.x, evento.y) == "nothing":
            self.mostrar_resumo()

    def warnings(self):
        return self._avisos

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
