"""Janela principal: monta as abas e guarda o que as tres compartilham."""
import tkinter as tk
from datetime import datetime
from tkinter import ttk

import log
import preferencias
from core import api
from core.reputacao import classificar_ibm
from i18n import t
from ui import tema
from ui.aba_hash import AbaHash
from ui.aba_ip import AbaIP
from ui.aba_url import AbaURL
from ui.navegadores import DriverIndisponivel, DriverPool
from ui.widgets import Botao, Cartao, MultilineInput, ResultTable, RotuloSecao

VERSAO = "v3.1"

_log = log.obter("app")


class IPCheckerApp(AbaIP, AbaHash, AbaURL):
    """Cada aba vive num mixin em ui/aba_*.py; aqui fica so a infraestrutura comum."""

    def __init__(self, root):
        self.root = root
        self.i18n_widgets = []
        self.current_page = "ip"
        self.stop_flag = False
        api.definir_cancelamento(lambda: self.stop_flag)
        root.title(f"IP Shark {VERSAO} - by @alexsilva.sh in Github")
        root.configure(bg=tema.FUNDO)

        self.historico = {"ip": [], "hash": [], "url": []}

        # Rodape fixo: a cota so aparecia no relatorio, depois de estourar.
        self.rodape_cota = tk.Label(self.root, bg=tema.FUNDO, fg=tema.TEXTO_SECUNDARIO,
                                    font=tema.fonte("menor"), anchor="e")
        self.rodape_cota.pack(side=tk.BOTTOM, fill="x", padx=tema.E3, pady=(0, tema.E1))

        corpo = tk.Frame(self.root, bg=tema.FUNDO)
        corpo.pack(fill=tk.BOTH, expand=True)
        self.lateral = tk.Frame(corpo, bg=tema.FUNDO_PAINEL, width=196)
        self.lateral.pack(side=tk.LEFT, fill=tk.Y)
        self.lateral.pack_propagate(False)
        self.area_conteudo = tk.Frame(corpo, bg=tema.FUNDO)
        self.area_conteudo.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        self.barra_topo = tk.Frame(self.area_conteudo, bg=tema.FUNDO)
        self.barra_topo.pack(fill="x", padx=tema.E4, pady=(tema.E3, 0))
        self.titulo_pagina = tk.Label(self.barra_topo, bg=tema.FUNDO, fg=tema.TEXTO,
                                      font=tema.fonte("titulo"), anchor="w")
        self.titulo_pagina.pack(side="left")
        # Preenchido pelo ponto de entrada com idioma e configuracao, alinhados a direita.
        self.acoes_topo = tk.Frame(self.barra_topo, bg=tema.FUNDO)
        self.acoes_topo.pack(side="right")
        self.banner = tk.Frame(self.area_conteudo, bg=tema.FUNDO_AVISO)
        self.banner_label = tk.Label(self.banner, bg=tema.FUNDO_AVISO, fg=tema.REVISAR,
                                     font=tema.fonte("corpo"), justify="left", wraplength=1000)
        self.banner_label.pack(side="left", padx=tema.E3, pady=tema.E2)

        self.tab_frame = tk.Frame(self.lateral, bg=tema.FUNDO_PAINEL)
        self.tab_frame.pack(fill="x", padx=tema.E2, pady=(tema.E4, 0))

        self.driver_pool = DriverPool(ao_degradar=self._avisar_pool_degradado)
        self._init_drivers_async()

        self._montar_aba_ip()
        self._montar_aba_hash()
        self._montar_aba_url()
        self._montar_lateral()
        self._mostrar_pagina("ip")

        # Enter quebra linha no campo multi-linha, entao a consulta fica no Ctrl+Enter.
        for campo, acao in ((self.entry, self.run_check),
                            (self.hash_entry, self.run_hash_check),
                            (self.url_entry, self.run_url_check)):
            campo.texto.bind("<Control-Return>", lambda e, a=acao: (a(), "break")[1])
        self.root.bind("<Escape>", lambda e: self.cancel_current())

        self._update_action_buttons()
        self.atualizar_rodape_cota()

    # ---------- cota ----------

    INTERVALO_RODAPE_MS = 2000

    def atualizar_rodape_cota(self, reagendar=True):
        """Mostra o que as APIs informam de cota. Fonte que nao informa nao aparece --
        rodape vazio significa 'ninguem contou ainda', nunca 'cota zerada'."""
        cotas = api.cotas_restantes()
        texto = ""
        if cotas:
            partes = " · ".join(f"{fonte}: {restante}" for fonte, restante in sorted(cotas.items()))
            texto = f"{t('quota_footer')} — {partes}"
        esgotada = any(restante == 0 for restante in cotas.values())
        self.rodape_cota.config(text=texto, fg=tema.REVISAR if esgotada else tema.TEXTO_SECUNDARIO)
        if reagendar:
            try:
                self.root.after(self.INTERVALO_RODAPE_MS, self.atualizar_rodape_cota)
            except tk.TclError:
                pass   # janela fechando

    # ---------- barra lateral ----------

    LIMITE_HISTORICO = 8

    def _montar_lateral(self):
        rodape = tk.Frame(self.lateral, bg=tema.FUNDO_PAINEL)
        rodape.pack(side=tk.BOTTOM, fill="x", padx=tema.E2, pady=tema.E3)

        aparencia = tk.Frame(rodape, bg=tema.FUNDO_PAINEL)
        aparencia.pack(fill="x", pady=(0, tema.E2))
        self.botao_tema = Botao(aparencia, command=self._alternar_tema)
        self.botao_tema.pack(side="left")
        Botao(aparencia, text="A-", command=lambda: self._ajustar_fonte(-1)).pack(
            side="left", padx=(tema.E1, 0))
        Botao(aparencia, text="A+", command=lambda: self._ajustar_fonte(1)).pack(
            side="left", padx=(tema.E1, 0))
        self._atualizar_botao_tema()

        # Slot que o ponto de entrada preenche com idioma e configuracao.
        self.lateral_rodape = rodape

        historico = tk.Frame(self.lateral, bg=tema.FUNDO_PAINEL)
        historico.pack(fill="both", expand=True, padx=tema.E2, pady=(tema.E5, 0))
        self.rotulo_historico = tk.Label(historico, text=t("history_title"), bg=tema.FUNDO_PAINEL,
                                         fg=tema.TEXTO_SECUNDARIO, font=tema.fonte("forte"),
                                         anchor="w")
        self.rotulo_historico.pack(fill="x", pady=(0, tema.E1))
        self._register_i18n(self.rotulo_historico, "history_title")
        self.lista_historico = tk.Frame(historico, bg=tema.FUNDO_PAINEL)
        self.lista_historico.pack(fill="both", expand=True)
        self._desenhar_historico()

    def _alternar_tema(self):
        tema.alternar(self.root)
        self._atualizar_botao_tema()
        self._desenhar_historico()
        preferencias.salvar(tema=tema.nome_atual())

    def _atualizar_botao_tema(self):
        claro = tema.nome_atual() == "claro"
        self.botao_tema.config(text="☾" if claro else "☀")

    def _ajustar_fonte(self, passo):
        # Salva a escala aplicada, nao a pedida: nos extremos ela nao muda.
        preferencias.salvar(escala=tema.definir_escala(tema.escala_atual() + passo))
        self._desenhar_historico()

    def registrar_historico(self, aba, texto, quantidade):
        """Guarda a entrada de uma varredura para o analista repetir sem recolar.

        So em memoria, de proposito: indicador de cliente nao vai para disco, a mesma
        regra que o registro em arquivo segue (ver src/log.py).
        """
        texto = (texto or "").strip()
        if not texto:
            return
        fila = self.historico[aba]
        fila[:] = [e for e in fila if e["texto"] != texto]
        fila.insert(0, {"texto": texto, "quantidade": quantidade,
                        "hora": datetime.now().strftime("%H:%M")})
        del fila[self.LIMITE_HISTORICO:]
        self._desenhar_historico()

    def _desenhar_historico(self):
        for filho in self.lista_historico.winfo_children():
            filho.destroy()
        entradas = self.historico.get(self.current_page, [])
        if not entradas:
            tk.Label(self.lista_historico, text=t("history_empty"), bg=tema.FUNDO_PAINEL,
                     fg=tema.TEXTO_SECUNDARIO, font=tema.fonte("menor"), anchor="w",
                     justify="left", wraplength=170).pack(fill="x")
            return
        for entrada in entradas:
            resumo = entrada["texto"].split()[0] if entrada["texto"].split() else ""
            if len(resumo) > 20:
                resumo = resumo[:19] + "…"
            if entrada["quantidade"] > 1:
                resumo += f" +{entrada['quantidade'] - 1}"
            item = tk.Label(self.lista_historico, text=f"{entrada['hora']}  {resumo}",
                            bg=tema.FUNDO_PAINEL, fg=tema.TEXTO, font=tema.fonte("menor"),
                            anchor="w", cursor="hand2")
            item.pack(fill="x", pady=(0, tema.E1))
            item.bind("<Button-1>", lambda _e, x=entrada["texto"]: self._restaurar_historico(x))
            item.bind("<Enter>", lambda _e, w=item: w.config(fg=tema.LINK))
            item.bind("<Leave>", lambda _e, w=item: w.config(fg=tema.TEXTO))

    def _restaurar_historico(self, texto):
        campos = {"ip": self.entry, "hash": self.hash_entry, "url": self.url_entry}
        campo = campos[self.current_page]
        campo.texto.delete("1.0", tk.END)
        campo.texto.insert("1.0", texto)
        campo.refresh()
        campo.focus_set()

    # ---------- navegacao entre abas ----------

    def _mostrar_pagina(self, nome):
        paginas = {"ip": (self.page_ip, self.ip_button),
                   "hash": (self.page_hash, self.hash_button),
                   "url": (self.page_url, self.url_button)}
        for chave, (pagina, botao) in paginas.items():
            if chave == nome:
                pagina.pack(fill=tk.BOTH, expand=True)
                botao.config(tom="nav_ativo")
            else:
                pagina.pack_forget()
                botao.config(tom="nav")
        self.current_page = nome
        self.titulo_pagina.config(text=t({"ip": "tab_ip", "hash": "tab_hash",
                                          "url": "tab_domain"}[nome]))
        self._desenhar_historico()

    # ---------- navegadores ----------

    def _init_drivers_async(self, count=3):
        self.driver_pool.iniciar_async()

    def _avisar_pool_degradado(self, vivos, tamanho, erro):
        chave = "drivers_none" if vivos == 0 else "drivers_degraded"
        self._ui(self.mostrar_aviso, t(chave).format(vivos=vivos, total=tamanho))
        if erro:
            _log.warning("pool degradado: %s de %s navegadores; ultimo erro: %s",
                         vivos, tamanho, erro)

    def mostrar_aviso(self, texto):
        self.banner_label.config(text=f"⚠ {texto}")
        self.banner.pack(fill="x", padx=tema.E4, pady=(tema.E2, 0), after=self.barra_topo)

    def _consultar_ibm(self, consulta, indicador):
        """(score, estado) do X-Force. Pool vazio vira fonte indisponivel em vez de travar.

        Pagina ilegivel e retentada como nas fontes HTTP; falta de navegador nao, que o
        emprestimo ja espera a sua vez por conta propria.
        """
        for _ in api.tentativas():
            try:
                with self.driver_pool.emprestar() as driver:
                    score = consulta(driver, indicador)
            except DriverIndisponivel:
                return None, api.FONTE_INDISPONIVEL
            estado = classificar_ibm(score)
            if estado != api.FONTE_INDISPONIVEL or self.stop_flag:
                break
        return (t("unknown") if estado == api.FONTE_SEM_DADOS else score), estado

    # ---------- interface ----------

    def _register_i18n(self, widget, key, attr="text"):
        self.i18n_widgets.append((widget, key, attr))

    def refresh_language(self):
        for widget, key, attr in self.i18n_widgets:
            try:
                value = t(key)
                if attr == "title":
                    widget.title(value)
                else:
                    widget.config(**{attr: value})
            except Exception:
                # Normal quando o widget ja foi destruido; suspeito quando e chave errada.
                _log.debug("widget nao aceitou a traducao de %r", key, exc_info=True)
        for tabela in (self.tabela_ip, self.tabela_hash, self.tabela_url):
            tabela.refresh_language()
        for campo in (self.entry, self.hash_entry, self.url_entry):
            campo.refresh()
        self.atualizar_rodape_cota(reagendar=False)
        self._mostrar_pagina(self.current_page)   # reetiqueta o titulo e o historico

    # ---------- cartoes que as tres abas compartilham ----------

    def _montar_entrada(self, pagina, chave_rotulo, contador):
        cartao = Cartao(pagina, "section_input", self._register_i18n)
        cartao.pack(fill="x", padx=tema.E4, pady=(tema.E3, tema.E2))
        rotulo = tk.Label(cartao.corpo, text=t(chave_rotulo), bg=tema.FUNDO_PAINEL,
                          fg=tema.TEXTO, font=tema.fonte("corpo"), anchor="w")
        rotulo.pack(fill="x", pady=(0, tema.E1))
        self._register_i18n(rotulo, chave_rotulo)
        campo = MultilineInput(cartao.corpo, contador)
        campo.pack(fill="x")
        return rotulo, campo

    def _montar_opcoes(self, pagina, chave_botao, comando):
        """Cartao de opcoes: grupo de fontes, grupo de relatorio e o botao de consulta.

        Devolve (botao, linha_de_fontes, linha_de_relatorio) para a aba pendurar os chips
        que sao dela -- a de dominio tem um a mais que as outras duas.
        """
        cartao = Cartao(pagina)
        cartao.pack(fill="x", padx=tema.E4, pady=(0, tema.E2))
        botao = Botao(cartao.corpo, text=t(chave_botao), command=comando, tom="primario")
        botao.pack(side="right", padx=(tema.E4, 0))
        self._register_i18n(botao, chave_botao)
        linhas = []
        for chave in ("section_sources", "section_report"):
            grupo = tk.Frame(cartao.corpo, bg=tema.FUNDO_PAINEL)
            grupo.pack(side="left", padx=(0, tema.E6))
            rotulo = RotuloSecao(grupo, chave)
            rotulo.pack(fill="x", pady=(0, tema.E2))
            self._register_i18n(rotulo, chave)
            linha = tk.Frame(grupo, bg=tema.FUNDO_PAINEL)
            linha.pack(anchor="w")
            linhas.append(linha)
        return botao, linhas[0], linhas[1]

    def _montar_resultados(self, pagina, colunas):
        """Cartao de resultados: progresso, status e tabela no mesmo bloco.

        O progresso morava solto entre os cartoes e ficava boiando na tela quando nao havia
        varredura em curso. Devolve (tabela, barra, rotulo_de_status).
        """
        cartao = Cartao(pagina, "section_results", self._register_i18n)
        cartao.pack(fill=tk.BOTH, expand=True, padx=tema.E4, pady=(0, tema.E2))
        barra = ttk.Progressbar(cartao.corpo, style="Scan.Horizontal.TProgressbar",
                                mode="determinate", maximum=1, value=0)
        barra.pack(fill="x")
        rotulo = ttk.Label(cartao.corpo, text="", style="Status.TLabel",
                           background=tema.FUNDO_PAINEL)
        rotulo.pack(anchor="w", pady=(tema.E1, tema.E2))
        tabela = ResultTable(cartao.corpo, colunas)
        tabela.pack(fill=tk.BOTH, expand=True)
        return tabela, barra, rotulo

    def _ui(self, fn, *args):
        """Agenda fn na thread da interface. Tk nao pode ser tocado pelas threads de varredura."""
        try:
            self.root.after(0, lambda: fn(*args))
        except tk.TclError:
            pass   # janela fechada no meio da varredura

    def _track_processing(self, em_andamento, valor, ativo, atualizar_status):
        def _aplicar():
            if ativo:
                em_andamento.add(valor)
            else:
                em_andamento.discard(valor)
            atualizar_status()
        self._ui(_aplicar)

    def _update_action_buttons(self):
        """Copiar/Exportar so com resultado na tela; Cancelar so durante a varredura."""
        grupos = (
            (self.tabela_ip, self.results_ip, self.scanning_ip,
             self.copy_button, self.save_button, self.cancel_button),
            (self.tabela_hash, self.results_hash, self.scanning_hash,
             self.hash_copy_button, self.hash_save_button, self.hash_cancel_button),
            (self.tabela_url, self.results_url, self.scanning_url,
             self.url_copy_button, self.url_save_button, self.url_cancel_button),
        )
        for tabela, resultados, varrendo, copiar, exportar, cancelar in grupos:
            copiar.config(state="disabled" if tabela.is_empty() else "normal")
            exportar.config(state="normal" if resultados else "disabled")
            cancelar.config(state="normal" if varrendo else "disabled")

    def cancel_current(self):
        """Esc cancela a varredura da aba visivel; sem varredura em andamento, nao faz nada."""
        if self.current_page == "hash":
            if self.scanning_hash:
                self.cancel_check_hash()
        elif self.current_page == "url":
            if self.scanning_url:
                self.cancel_check_url()
        elif self.scanning_ip:
            self.cancel_check()

    def on_close(self):
        try:
            self.driver_pool.encerrar()
        except Exception:
            _log.exception("falha ao encerrar o pool de navegadores")
        finally:
            self.root.destroy()
