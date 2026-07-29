"""Janela principal: monta as abas e guarda o que as tres compartilham."""
import tkinter as tk
from tkinter import ttk

import log
from core import api
from core.reputacao import classificar_ibm
from i18n import t
from ui import tema
from ui.aba_hash import AbaHash
from ui.aba_ip import AbaIP
from ui.aba_url import AbaURL
from ui.navegadores import DriverIndisponivel, DriverPool

VERSAO = "v3.1"

_log = log.obter("app")


class IPCheckerApp(AbaIP, AbaHash, AbaURL):
    """Cada aba vive num mixin em ui/aba_*.py; aqui fica so a infraestrutura comum."""

    def __init__(self, root):
        self.root = root
        self.i18n_widgets = []
        self.current_page = "ip"
        self.stop_flag = False
        root.title(f"IP Shark {VERSAO} - by @alexsilva.sh in Github")
        root.configure(bg=tema.FUNDO)

        self.tab_frame = tk.Frame(self.root, bg=tema.FUNDO)
        self.tab_frame.pack(pady=(5, 0))
        self.banner = tk.Frame(self.root, bg=tema.FUNDO_AVISO)
        self.banner_label = tk.Label(self.banner, bg=tema.FUNDO_AVISO, fg=tema.REVISAR,
                                     font=("Segoe UI", 9), justify="left", wraplength=1000)
        self.banner_label.pack(side="left", padx=12, pady=6)

        self.driver_pool = DriverPool(ao_degradar=self._avisar_pool_degradado)
        self._init_drivers_async()

        self._montar_aba_ip()
        self._montar_aba_hash()
        self._montar_aba_url()
        self._mostrar_pagina("ip")

        # Enter quebra linha no campo multi-linha, entao a consulta fica no Ctrl+Enter.
        for campo, acao in ((self.entry, self.run_check),
                            (self.hash_entry, self.run_hash_check),
                            (self.url_entry, self.run_url_check)):
            campo.texto.bind("<Control-Return>", lambda e, a=acao: (a(), "break")[1])
        self.root.bind("<Escape>", lambda e: self.cancel_current())

        self._update_action_buttons()

    # ---------- navegacao entre abas ----------

    def _mostrar_pagina(self, nome):
        paginas = {"ip": (self.page_ip, self.ip_button),
                   "hash": (self.page_hash, self.hash_button),
                   "url": (self.page_url, self.url_button)}
        for chave, (pagina, botao) in paginas.items():
            if chave == nome:
                pagina.pack(fill=tk.BOTH, expand=True)
                botao.config(style="NavActive.TButton")
            else:
                pagina.pack_forget()
                botao.config(style="Nav.TButton")
        self.current_page = nome

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
        self.banner.pack(fill="x", padx=10, pady=(6, 0), after=self.tab_frame)

    def _consultar_ibm(self, consulta, indicador):
        """(score, estado) do X-Force. Pool vazio vira fonte indisponivel em vez de travar."""
        try:
            with self.driver_pool.emprestar() as driver:
                score = consulta(driver, indicador)
        except DriverIndisponivel:
            return None, api.FONTE_INDISPONIVEL
        estado = classificar_ibm(score)
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

    def _montar_progresso(self, pagina):
        quadro = tk.Frame(pagina, bg=tema.FUNDO)
        quadro.pack(fill="x", padx=10, pady=(2, 6))
        barra = ttk.Progressbar(quadro, style="Scan.Horizontal.TProgressbar",
                                mode="determinate", maximum=1, value=0)
        barra.pack(fill="x")
        rotulo = ttk.Label(quadro, text="", style="Status.TLabel")
        rotulo.pack(anchor="w", pady=(3, 0))
        return barra, rotulo

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
