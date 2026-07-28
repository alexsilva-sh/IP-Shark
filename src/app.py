"""Janela principal: orquestra as varreduras e liga o nucleo a interface."""
import base64
import ipaddress
import re
import socket
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread
from tkinter import messagebox, ttk
from urllib.parse import urlparse

import pyperclip
import requests

from core import api
from core.api import (
    check_hash_alienvault,
    check_hash_virustotal,
    check_ip_abuseipdb,
    check_ip_virustotal,
    check_url_alienvault,
    check_url_virustotal,
    get_location,
    safe_get,
)
from core.navegador import check_hash_ibm, check_hash_joesandbox, check_ip_ibm, check_url_ibm
from core.reputacao import build_ip_result, classificar_ibm, get_domain_from_abuseipdb, is_valid_ip
from i18n import plural, t
from services.exportacao import salvar_planilha, salvar_planilha_dominios
from ui import tema
from ui.apresentacao import (
    VERDICT_KEYS,
    coluna_fonte,
    colunas_ip,
    contar_dominios,
    contar_hashes,
    contar_ips,
    dividir_entrada,
    fontes_em_cota,
    linha_planilha_ip,
    relatorio_ip,
    texto_fonte,
)
from ui.navegadores import DriverIndisponivel, DriverPool
from ui.widgets import MultilineInput, ResultTable, ToggleSwitch

VERSAO = "v3.1"


class IPCheckerApp:
    def _init_drivers_async(self, count=3):
        self.driver_pool.iniciar_async()

    def _avisar_pool_degradado(self, vivos, tamanho, erro):
        chave = "drivers_none" if vivos == 0 else "drivers_degraded"
        self._ui(self.mostrar_aviso, t(chave).format(vivos=vivos, total=tamanho))
        if erro:
            print(f"[AVISO] Falha ao iniciar navegador: {erro}")

    def mostrar_aviso(self, texto):
        self.banner_label.config(text=f"⚠ {texto}")
        self.banner.pack(fill="x", padx=10, pady=(6, 0), after=self.tab_frame)

    def refresh_language(self):
        for widget, key, attr in self.i18n_widgets:
            try:
                value = t(key)
                if attr == "title":
                    widget.title(value)
                else:
                    widget.config(**{attr: value})
            except Exception:
                pass
        for tabela in (self.tabela_ip, self.tabela_hash, self.tabela_url):
            tabela.refresh_language()
        for campo in (self.entry, self.hash_entry, self.url_entry):
            campo.refresh()
    def _register_i18n(self, widget, key, attr="text"):
        self.i18n_widgets.append((widget, key, attr))
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

    def __init__(self, root):
        self.root = root
        self.i18n_widgets = []
        self.current_page = "ip"
        # Toggles congelados no inicio da varredura: threads nao podem ler BooleanVar.
        self.ibm_ip_ativo = True
        self.ibm_hash_ativo = True
        self.ibm_url_ativo = True
        self.check_ips_url_ativo = True
        self.ip_results_by_domain = {}
        self.currently_processing = set()
        self.bad_ips = set()
        self.review_ips = set()
        self.review_urls = set()
        self.ignorados_ip = []
        self.ignorados_hash = []
        self.incompletos_ip = set()
        self.incompletos_hash = set()
        self.incompletos_url = set()
        self.cota_ip = set()
        self.cota_hash = set()
        self.cota_url = set()
        self.total_ip = self.feitos_ip = 0
        self.total_hash = self.feitos_hash = 0
        self.total_url = self.feitos_url = 0
        root.title(f"IP Shark {VERSAO} - by @alexsilva.sh in Github")
        self.root.configure(bg=tema.FUNDO)        
        self.currently_processing = set()
        self.root = root
        root.title(f"IP Shark {VERSAO} - by @alexsilva.sh in Github")
        self.root.configure(bg=tema.FUNDO)
        self.tab_frame = tk.Frame(self.root, bg=tema.FUNDO)
        self.tab_frame.pack(pady=(5, 0))
        self.banner = tk.Frame(self.root, bg=tema.FUNDO_AVISO)
        self.banner_label = tk.Label(self.banner, bg=tema.FUNDO_AVISO, fg=tema.REVISAR,
                                     font=("Segoe UI", 9), justify="left", wraplength=1000)
        self.banner_label.pack(side="left", padx=12, pady=6)
        self.ip_button = ttk.Button(self.tab_frame,text=t("tab_ip"),command=self.show_ip_page,style="NavActive.TButton")
        self.ip_button.grid(row=0,column=0,padx=5)        
        self._register_i18n(self.ip_button, "tab_ip")
        self.hash_button = ttk.Button(self.tab_frame,text=t("tab_hash"),command=self.show_hash_page,style="Nav.TButton")
        self.hash_button.grid(row=0, column=1, padx=5)
        self.page_ip = tk.Frame(root, bg=tema.FUNDO)
        self.page_ip.pack(fill=tk.BOTH, expand=True)
        self.page_hash = tk.Frame(root, bg=tema.FUNDO)
        self.page_hash.pack_forget()
        self.driver_pool = DriverPool(ao_degradar=self._avisar_pool_degradado)
        self._init_drivers_async()

        # CONTEUDO DA ABA IP
        self.input_label = ttk.Label(self.page_ip,text=t("paste_ips"),style="Title.TLabel")
        self.input_label.pack(pady=(10,2))
        self._register_i18n(self.input_label, "paste_ips")
        self.entry = MultilineInput(self.page_ip, contar_ips)
        self.entry.pack(pady=6, padx=20, fill="x")

        # ---------- interruptores (aba IP) ---------------------------
        toggles_ip = tk.Frame(self.page_ip, bg=tema.FUNDO)
        toggles_ip.pack(pady=6)
        self.ibm_var_ip = tk.BooleanVar(value=True)
        self.toggle_ibm_ip = ToggleSwitch(toggles_ip, text=t("toggle_ibm"), variable=self.ibm_var_ip)
        self.toggle_ibm_ip.pack(side="left", padx=(0,15))
        self._register_i18n(self.toggle_ibm_ip.label, "toggle_ibm")
        col_ip = tk.Frame(toggles_ip, bg=tema.FUNDO)
        col_ip.pack(side="left")
        self.pre_var_ip = tk.BooleanVar(value=False)
        self.toggle_pre_ip = ToggleSwitch(col_ip, text=t("toggle_pre_analysis"), variable=self.pre_var_ip)
        self.toggle_pre_ip.pack(anchor="w")
        self._register_i18n(self.toggle_pre_ip.label, "toggle_pre_analysis")
        self.mss_var_ip = tk.BooleanVar(value=False)
        self.mss_ip_switch = ToggleSwitch(col_ip, text=t("toggle_has_mss"), variable=self.mss_var_ip, state="disabled")
        self.mss_ip_switch.pack(anchor="w")
        self._register_i18n(self.mss_ip_switch.label, "toggle_has_mss")
        self.pre_var_ip.trace_add("write", self._update_mss_state_ip)
        self.check_button = ttk.Button(self.page_ip,text=t("btn_check_ip"),command=self.run_check,style="Primary.TButton")
        self.check_button.pack(pady=12)
        self._register_i18n(self.check_button, "btn_check_ip")        
        self.progress_ip, self.status_label = self._montar_progresso(self.page_ip)
        self.button_frame = tk.Frame(self.page_ip, bg=tema.FUNDO)
        self.button_frame.pack(side=tk.BOTTOM, pady=10, fill=tk.X)
        self.button_frame.grid_columnconfigure(0, weight=1)
        self.button_frame.grid_columnconfigure(4, weight=1)
        self.tabela_ip = ResultTable(self.page_ip, [
            ("#0", "csv_ip", 210, "w"),
            ("veredito", "col_verdict", 160, "w"),
            ("abuse", "col_abuse", 95, "center"),
            ("vt", "col_vt", 95, "center"),
            ("ibm", "col_ibm", 85, "center"),
            ("pais", "col_country", 140, "w"),
        ])
        self.tabela_ip.pack(padx=10, pady=(0, 5), fill=tk.BOTH, expand=True)

        self.copy_button = ttk.Button(self.button_frame,text=t("btn_copy"),command=self.copy_output,style="Secondary.TButton")
        self.copy_button.grid(row=0,column=1,padx=10)
        self._register_i18n(self.copy_button, "btn_copy")
        self.save_button = ttk.Button(self.button_frame,text=t("btn_export"),command=self.save_results,style="Secondary.TButton")
        self.save_button.grid(row=0,column=2,padx=10)
        self._register_i18n(self.save_button, "btn_export")
        self.cancel_button = ttk.Button(self.button_frame,text=t("btn_cancel"),command=self.cancel_check,style="Danger.TButton")
        self.cancel_button.grid(row=0,column=3,padx=10)
        self._register_i18n(self.cancel_button, "btn_cancel")
        self.results_ip = []
        self.results_hash = []
        self.results_url = []
        self.stop_flag = False
        self.scanning_ip = False
        self.scanning_hash = False
        self.scanning_url = False

        # CONTEUDO DA ABA HASH
        self.input_label_hash = ttk.Label(self.page_hash,text=t("paste_hashes"),style="Title.TLabel")
        self._register_i18n(self.hash_button, "tab_hash")
        self._register_i18n(self.input_label_hash, "paste_hashes")
        self.input_label_hash.pack(pady=(10, 2))
        self.hash_entry = MultilineInput(self.page_hash, contar_hashes)
        self.hash_entry.pack(pady=6, padx=20, fill="x")

        # ---------- interruptores (aba HASH) ---------------------------
        toggles_hash = tk.Frame(self.page_hash, bg=tema.FUNDO)
        toggles_hash.pack(pady=6)

        self.ibm_var_hash = tk.BooleanVar(value=True)
        self.toggle_ibm_hash = ToggleSwitch(toggles_hash, text=t("toggle_ibm"), variable=self.ibm_var_hash)
        self.toggle_ibm_hash.pack(side="left", padx=(0,15))
        self._register_i18n(self.toggle_ibm_hash.label, "toggle_ibm")

        col_hash = tk.Frame(toggles_hash, bg=tema.FUNDO)
        col_hash.pack(side="left")

        self.pre_var_hash = tk.BooleanVar(value=False)
        self.toggle_pre_hash = ToggleSwitch(col_hash, text=t("toggle_pre_analysis"), variable=self.pre_var_hash)
        self.toggle_pre_hash.pack(anchor="w")
        self._register_i18n(self.toggle_pre_hash.label, "toggle_pre_analysis")

        self.mss_var_hash = tk.BooleanVar(value=False)
        self.mss_hash_switch = ToggleSwitch(col_hash, text=t("toggle_has_mss"), variable=self.mss_var_hash, state="disabled")
        self.mss_hash_switch.pack(anchor="w")
        self._register_i18n(self.mss_hash_switch.label, "toggle_has_mss")

        self.pre_var_hash.trace_add("write", self._update_mss_state_hash)

        self.hash_button_action = ttk.Button(self.page_hash,text=t("btn_check_hash"),command=self.run_hash_check,style="Primary.TButton")
        self.hash_button_action.pack(pady=12)
        self._register_i18n(self.hash_button_action, "btn_check_hash")
        self.currently_processing_hashes = set()
        self.progress_hash, self.hash_status_label = self._montar_progresso(self.page_hash)

        self.hash_button_frame = tk.Frame(self.page_hash, bg=tema.FUNDO)
        self.hash_button_frame.pack(side=tk.BOTTOM, pady=10, fill=tk.X)
        self.hash_button_frame.grid_columnconfigure(0, weight=1)
        self.hash_button_frame.grid_columnconfigure(4, weight=1)
        self.tabela_hash = ResultTable(self.page_hash, [
            ("#0", "csv_hash", 300, "w"),
            ("veredito", "col_verdict", 160, "w"),
            ("vt", "col_vt", 95, "center"),
            ("ibm", "col_ibm", 85, "center"),
            ("alien", "col_alien", 95, "center"),
            ("arquivo", "col_file", 200, "w"),
        ])
        self.tabela_hash.pack(padx=10, pady=(0, 5), fill=tk.BOTH, expand=True)

        self.hash_copy_button = ttk.Button(self.hash_button_frame,text=t("btn_copy"),command=self.copy_hash_output,style="Secondary.TButton")
        self.hash_copy_button.grid(row=0, column=1, padx=10)
        self._register_i18n(self.hash_copy_button, "btn_copy")
        
        self.hash_save_button = ttk.Button(self.hash_button_frame,text=t("btn_export"),command=self.save_hash_results,style="Secondary.TButton")
        self.hash_save_button.grid(row=0, column=2, padx=10)
        self._register_i18n(self.hash_save_button, "btn_export")
        
        self.hash_cancel_button = ttk.Button(self.hash_button_frame,text=t("btn_cancel"),command=self.cancel_check_hash,style="Danger.TButton")
        self.hash_cancel_button.grid(row=0, column=3, padx=10)
        self._register_i18n(self.hash_cancel_button, "btn_cancel")
        
        # CONTEUDO DA ABA DOMINIO
        self.url_button = ttk.Button(self.tab_frame,text=t("tab_domain"),command=self.show_url_page,style="Nav.TButton")
        self.url_button.grid(row=0, column=2, padx=5)
        self.page_url = tk.Frame(root, bg=tema.FUNDO)
        self.page_url.pack_forget()
        self.input_label_url = ttk.Label(self.page_url,text=t("paste_domains"),style="Title.TLabel")
        self._register_i18n(self.url_button, "tab_domain")
        self._register_i18n(self.input_label_url, "paste_domains")
        self.input_label_url.pack(pady=(10, 2))
        self.url_entry = MultilineInput(self.page_url, contar_dominios)
        self.url_entry.pack(pady=6, padx=20, fill="x")
        toggles_url = tk.Frame(self.page_url, bg=tema.FUNDO)
        toggles_url.pack(pady=6)
        self.ibm_var_url = tk.BooleanVar(value=True)
        self.toggle_ibm_url = ToggleSwitch(toggles_url, text=t("toggle_ibm"), variable=self.ibm_var_url)
        self.toggle_ibm_url.pack(side="left", padx=(0,15))
        self._register_i18n(self.toggle_ibm_url.label, "toggle_ibm")

        self.check_ips_var_url = tk.BooleanVar(value=True)
        self.toggle_check_ips = ToggleSwitch(
            toggles_url,
            text=t("toggle_check_ips"),
            variable=self.check_ips_var_url
        )
        self.toggle_check_ips.pack(side="left", padx=(0, 15))
        self._register_i18n(self.toggle_check_ips.label, "toggle_check_ips")
        col_url = tk.Frame(toggles_url, bg=tema.FUNDO)
        col_url.pack(side="left")
        self.pre_var_url = tk.BooleanVar(value=False)
        self.toggle_pre_url = ToggleSwitch(col_url, text=t("toggle_pre_analysis"), variable=self.pre_var_url)
        self.toggle_pre_url.pack(anchor="w")
        self._register_i18n(self.toggle_pre_url.label, "toggle_pre_analysis")

        self.mss_var_url = tk.BooleanVar(value=False)
        self.mss_url_switch = ToggleSwitch(col_url, text=t("toggle_has_mss"), variable=self.mss_var_url, state="disabled")
        self.mss_url_switch.pack(anchor="w")
        self._register_i18n(self.mss_url_switch.label, "toggle_has_mss")

        self.pre_var_url.trace_add("write", self._update_mss_state_url)
        
        self.url_button_action = ttk.Button(self.page_url,text=t("btn_check_domain"),command=self.run_url_check,style="Primary.TButton")
        self.url_button_action.pack(pady=12)
        self._register_i18n(self.url_button_action, "btn_check_domain")
        self.progress_url, self.url_status_label = self._montar_progresso(self.page_url)
        self.url_button_frame = tk.Frame(self.page_url, bg=tema.FUNDO)
        self.url_button_frame.pack(side=tk.BOTTOM, pady=10, fill=tk.X)
        self.tabela_url = ResultTable(self.page_url, [
            ("#0", "csv_domain", 260, "w"),
            ("veredito", "col_verdict", 160, "w"),
            ("abuse", "col_abuse", 95, "center"),
            ("vt", "col_vt", 95, "center"),
            ("ibm", "col_ibm", 85, "center"),
            ("alien", "col_alien", 95, "center"),
        ])
        self.tabela_url.pack(padx=10, pady=(0, 5), fill=tk.BOTH, expand=True)

        self.url_button_frame.grid_columnconfigure(0, weight=1)
        self.url_button_frame.grid_columnconfigure(4, weight=1)
        self.url_copy_button = ttk.Button(self.url_button_frame,text=t("btn_copy"),command=self.copy_url_output,style="Secondary.TButton")
        self.url_copy_button.grid(row=0, column=1, padx=10)
        self._register_i18n(self.url_copy_button, "btn_copy")

        self.url_save_button = ttk.Button(self.url_button_frame,text=t("btn_export"),command=self.save_url_results,style="Secondary.TButton")
        self.url_save_button.grid(row=0, column=2, padx=10)
        self._register_i18n(self.url_save_button, "btn_export")

        self.url_cancel_button = ttk.Button(self.url_button_frame,text=t("btn_cancel"),command=self.cancel_check_url,style="Danger.TButton")
        self.url_cancel_button.grid(row=0, column=3, padx=10)
        self._register_i18n(self.url_cancel_button, "btn_cancel")
        self.currently_processing_urls = set()
        self.ip_button.config(style="NavActive.TButton")
        self.hash_button.config(style="Nav.TButton")
        self.url_button.config(style="Nav.TButton")

        # Enter quebra linha no campo multi-linha, entao a consulta fica no Ctrl+Enter.
        for campo, acao in ((self.entry, self.run_check),
                            (self.hash_entry, self.run_hash_check),
                            (self.url_entry, self.run_url_check)):
            campo.texto.bind("<Control-Return>", lambda e, a=acao: (a(), "break")[1])
        self.root.bind("<Escape>", lambda e: self.cancel_current())

        self._update_action_buttons()

    def _update_mss_state_hash(self, *args):
        if self.pre_var_hash.get():
            self.mss_hash_switch.set_state("normal")
        else:
            self.mss_hash_switch.set_state("disabled")    
        
    def _update_mss_state_ip(self, *args):
        if self.pre_var_ip.get():
            self.mss_ip_switch.set_state("normal")
        else:
            self.mss_ip_switch.set_state("disabled")

    def _update_mss_state_url(self, *args):
        if self.pre_var_url.get():
            self.mss_url_switch.set_state("normal")
        else:
            self.mss_url_switch.set_state("disabled")

    def show_ip_page(self):
        self.page_hash.pack_forget()
        self.page_url.pack_forget()
        self.page_ip.pack(fill=tk.BOTH, expand=True)
        self.current_page = "ip"
        self.ip_button.config(style="NavActive.TButton")
        self.hash_button.config(style="Nav.TButton")
        self.url_button.config(style="Nav.TButton")

    def show_hash_page(self):
        self.page_ip.pack_forget()
        self.page_url.pack_forget()
        self.page_hash.pack(fill=tk.BOTH, expand=True)
        self.current_page = "hash"
        self.ip_button.config(style="Nav.TButton")
        self.hash_button.config(style="NavActive.TButton")
        self.url_button.config(style="Nav.TButton")

    def show_url_page(self):
        self.page_ip.pack_forget()
        self.page_hash.pack_forget()
        self.page_url.pack(fill=tk.BOTH, expand=True)
        self.current_page = "url"
        self.ip_button.config(style="Nav.TButton")
        self.hash_button.config(style="Nav.TButton")
        self.url_button.config(style="NavActive.TButton")

    def run_hash_check(self):
        if self.scanning_hash:
            messagebox.showwarning(t("done"), t("scan_already_running_hash"))
            return
        self.bad_hashes = set()
        self.incompletos_hash = set()
        self.cota_hash = set()
        self.tabela_hash.clear()
        hash_list, invalid_hashes = [], []
        for h in [item.lower() for item in dividir_entrada(self.hash_entry.get_text())]:
            if re.fullmatch(r"[a-fA-F0-9]{32,64}", h):
                hash_list.append(h)
            else:
                invalid_hashes.append(h)
        if not hash_list:
            messagebox.showerror(t("error"), t("no_valid_hash"))
            return
        self.ignorados_hash = invalid_hashes
        self.results_hash = []
        self.stop_flag = False
        self.currently_processing_hashes.clear()
        self.hash_status_label.config(text="")
        self.scanning_hash = True
        self.ibm_hash_ativo = self.ibm_var_hash.get()
        self.total_hash, self.feitos_hash = len(hash_list), 0
        self.hash_button_action.config(state="disabled")
        self._update_action_buttons()
        self.update_status_label_hash()
        def thread_run():
            try:
                for i, h in enumerate(hash_list):
                    if self.stop_flag:
                        break
                    self._track_processing(self.currently_processing_hashes, h, True,
                                           self.update_status_label_hash)
                    texto, status, colunas, estados = self.process_hash(h, i + 1, total_hashes=len(hash_list))
                    if self.stop_flag:
                        break
                    if status == "bad":
                        self.bad_hashes.add(h)
                    elif status == "incompleto":
                        self.incompletos_hash.add(h)
                    self.cota_hash.update(fontes_em_cota(estados))
                    self._track_processing(self.currently_processing_hashes, h, False,
                                           self.update_status_label_hash)
                    self._ui(self._linha_hash, i + 1, colunas, texto, status)
                if not self.stop_flag:
                    self._ui(self._finish_hash_scan)
            finally:
                self.scanning_hash = False
                self._ui(self._scan_stopped_hash)
        Thread(target=thread_run, daemon=True).start()

    def _linha_hash(self, indice, colunas, texto, status):
        self.tabela_hash.add(f"hash-{indice}", colunas, texto, status)
        self.feitos_hash += 1
        self.update_status_label_hash()
        self._update_action_buttons()

    def _finish_hash_scan(self):
        self._append_analysis_hash()
        self.progress_hash.config(value=self.total_hash)
        self.hash_status_label.config(text=f"✅ {t('hash_scan_finished')}")

    def _scan_stopped_hash(self):
        self.hash_button_action.config(state="normal")
        self._update_action_buttons()

    def _append_analysis_hash(self):
        blocos = []
        if self.cota_hash:
            blocos.append(t("quota_warning").format(fontes=", ".join(sorted(self.cota_hash))))
        if self.ignorados_hash:
            blocos.append(f"{t('skipped_items')}: {', '.join(self.ignorados_hash)}")
        if self.incompletos_hash:
            blocos.append(t("incomplete_review").format(lista=", ".join(sorted(self.incompletos_hash))))
        if self.pre_var_hash.get():
            if self.bad_hashes:
                chave = "hash_bad_mss" if self.mss_var_hash.get() else "hash_bad_no_mss"
                blocos.append(plural(chave, self.bad_hashes))
            elif not self.incompletos_hash:
                blocos.append(plural("hash_clean", self.results_hash))
        self.tabela_hash.set_preamble("\n\n".join(blocos))

    def run_url_check(self):
        if self.scanning_url:
            messagebox.showwarning(t("done"), t("scan_already_running_domain"))
            return
        self.results_url.clear()
        self.bad_urls = set()
        self.review_urls = set()
        self.incompletos_url = set()
        self.cota_url = set()
        self.ip_results_by_domain = {}
        self.tabela_url.clear()
        url_list = dividir_entrada(self.url_entry.get_text())
        if not url_list:
            messagebox.showerror(t("error"), t("no_domain"))
            return
        self.stop_flag = False
        self.currently_processing_urls.clear()
        self.url_status_label.config(text="")
        self.scanning_url = True
        self.ibm_url_ativo = self.ibm_var_url.get()
        self.check_ips_url_ativo = self.check_ips_var_url.get()
        self.total_url, self.feitos_url = len(url_list), 0
        self.url_button_action.config(state="disabled")
        self._update_action_buttons()
        self.update_status_label_url()
        def thread_run():
            try:
                for i, raw_url in enumerate(url_list):
                    if self.stop_flag:
                        break
                    temp_url_for_parse = raw_url
                    if not re.match(r'^\w+://', temp_url_for_parse):
                        temp_url_for_parse = 'http://' + temp_url_for_parse
                    try:
                        parsed_initial = urlparse(temp_url_for_parse)
                        extracted_domain = (parsed_initial.netloc or parsed_initial.path).split(':')[0]
                        if extracted_domain:
                            url = extracted_domain
                        else:
                            url = raw_url
                    except Exception:
                        url = raw_url
                    self._track_processing(self.currently_processing_urls, url, True,
                                           self.update_status_label_url)
                    if self.stop_flag:
                        break
                    result_vt, estado_vt = check_url_virustotal(url)
                    if self.stop_flag:
                        break
                    vt_score = result_vt.get("score")
                    ibm_score, estado_ibm = "-", None
                    if self.ibm_url_ativo and not self.stop_flag:
                        try:
                            with self.driver_pool.emprestar() as driver:
                                ibm_score = check_url_ibm(driver, url)
                            estado_ibm = classificar_ibm(ibm_score)
                            if estado_ibm == api.FONTE_SEM_DADOS:
                                ibm_score = t("unknown")
                        except DriverIndisponivel:
                            ibm_score, estado_ibm = None, api.FONTE_INDISPONIVEL
                    if self.stop_flag:
                        break
                    alien_score, alien_link, estado_alien = check_url_alienvault(url)
                    vt_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                    vt_link = f"https://www.virustotal.com/gui/url/{vt_id}"
                    ibm_link = f"https://exchange.xforce.ibmcloud.com/url/{url}"
                    estados = {"vt": estado_vt, "ibm": estado_ibm, "alien": estado_alien}
                    output, status, colunas = self.process_url(
                        i + 1, url, vt_score, ibm_score, vt_link, ibm_link,
                        alien_score, alien_link, estados, total_urls=len(url_list))
                    if status == "bad":
                        self.bad_urls.add(url)
                    elif status == "incompleto":
                        self.incompletos_url.add(url)
                    self.cota_url.update(fontes_em_cota(estados))
                    self._track_processing(self.currently_processing_urls, url, False,
                                           self.update_status_label_url)
                    vt_texto = texto_fonte(vt_score, estado_vt)
                    alien_texto = texto_fonte(alien_score, estado_alien)
                    if self.ibm_url_ativo:
                        self.results_url.append([url, vt_texto, texto_fonte(ibm_score, estado_ibm), alien_texto, vt_link, ibm_link, alien_link])
                    else:
                        self.results_url.append([url, vt_texto, alien_texto, vt_link, alien_link])
                    self._ui(self._linha_url, i + 1, colunas, output, status)
                    if self.check_ips_url_ativo and not self.stop_flag:
                        domain = url
                        resolved_ips = self._resolve_domain_via_google_dns(domain)
                        if not resolved_ips:
                            resolved_ips = self._resolve_domain_with_socket(domain)
                        resolved_ips = sorted(set(resolved_ips))
                        self.ip_results_by_domain[domain] = []
                        if not resolved_ips:
                            self._ui(self._linha_url_filha, i + 1, 0,
                                     (t("domain_no_ip"), t("verdict_unknown"), "-", "-", "-", "-"),
                                     f"[{domain}] {t('domain_no_ip')}", "unknown")
                        for j, ip in enumerate(resolved_ips, 1):
                            if self.stop_flag:
                                break
                            ip_output, ip_status, ip_csv_data, ip_colunas, ip_estados = self.process_url_ip_associated(ip, domain)
                            self._ui(self._linha_url_filha, i + 1, j, ip_colunas,
                                     ip_output.lstrip("\n"), ip_status)
                            self.cota_url.update(fontes_em_cota(ip_estados))
                            if ip_status == "bad":
                                self.bad_urls.add(f"{ip} ({t('associated_to_domain')} {domain})")
                            if ip_status == "whitelisted_bad":
                                self.review_urls.add(ip)
                            if ip_status in ("incompleto", "unknown"):
                                self.incompletos_url.add(ip)
                            if ip_csv_data:
                                self.ip_results_by_domain[domain].append(ip_csv_data)
                if not self.stop_flag:
                    self._ui(self._finish_url_scan)
            finally:
                self.scanning_url = False
                self._ui(self._scan_stopped_url)
        Thread(target=thread_run, daemon=True).start()

    def _linha_url(self, indice, colunas, texto, status):
        self.tabela_url.add(f"url-{indice}", colunas, texto, status)
        self.feitos_url += 1
        self.update_status_label_url()
        self._update_action_buttons()

    def _linha_url_filha(self, indice, sub, colunas, texto, status):
        self.tabela_url.add(f"url-{indice}-ip-{sub}", colunas, texto, status,
                            parent=f"url-{indice}")

    def _finish_url_scan(self):
        self._append_analysis_url()
        self.progress_url.config(value=self.total_url)
        self.url_status_label.config(text=f"✅ {t('domain_scan_finished')}")

    def _scan_stopped_url(self):
        self.url_button_action.config(state="normal")
        self._update_action_buttons()

    def _append_analysis_url(self):
        blocos = []
        if self.cota_url:
            blocos.append(t("quota_warning").format(fontes=", ".join(sorted(self.cota_url))))
        if self.incompletos_url:
            blocos.append(t("incomplete_review").format(lista=", ".join(sorted(self.incompletos_url))))
        if not self.pre_var_url.get():
            self.tabela_url.set_preamble("\n\n".join(blocos))
            return
        if self.bad_urls:
            chave = "url_bad_mss" if self.mss_var_url.get() else "url_bad_no_mss"
            blocos.append(plural(chave, self.bad_urls))
        if self.review_urls:
            blocos.append(plural("ip_whitelist_review", self.review_urls))
        if not self.bad_urls and not self.review_urls and not self.incompletos_url:
            blocos.append(plural("url_clean", self.results_url))
        self.tabela_url.set_preamble("\n\n".join(blocos))

    def update_status_label_url(self):
        if not self.scanning_url:
            return
        self.progress_url.config(maximum=max(self.total_url, 1), value=self.feitos_url)
        partes = [t("progress_done").format(feitos=self.feitos_url, total=self.total_url)]
        if self.currently_processing_urls:
            partes.append(f"{t('checking_domains')}: {' | '.join(sorted(self.currently_processing_urls))}")
        self.url_status_label.config(text=" · ".join(partes))

    def copy_url_output(self):
        pyperclip.copy(self.tabela_url.report())

    def cancel_check_url(self):
        self.stop_flag = True
        self.url_status_label.config(text=f"❌ {t('scan_cancelled')}")
        self.scanning_url = False
        self.url_button_action.config(state="normal")
        self._update_action_buttons()
    def process_url(self, index, url, vt_score, ibm_score, vt_link, ibm_link,
                    alien_score, alien_link, estados, total_urls=1):
        estado_vt = estados.get("vt")
        estado_ibm = estados.get("ibm")
        estado_alien = estados.get("alien")

        is_malicious = False
        if estado_vt == api.FONTE_OK and (vt_score or 0) > 0:
            is_malicious = True
        if estado_ibm == api.FONTE_OK:
            try:
                if float(ibm_score) >= 2:
                    is_malicious = True
            except (ValueError, TypeError):
                if str(ibm_score).strip().lower() in ("high", "medium"):
                    is_malicious = True
        if estado_alien == api.FONTE_OK and str(alien_score).strip() not in ("0", "-", ""):
            is_malicious = True

        fontes_fora = [nome for nome, estado in (
            ("VirusTotal", estado_vt), ("IBM X-Force", estado_ibm), ("AlienVault", estado_alien)
        ) if estado in api.ESTADOS_SEM_RESPOSTA]
        status = "bad" if is_malicious else ("incompleto" if fontes_fora else "clean")
        reputation = {"bad": t("reputation_bad"),
                      "incompleto": t("verdict_incomplete")}.get(status, t("reputation_clean"))

        if total_urls == 1:
            first_line = f"[{url}] - {reputation}"
        else:
            first_line = f"[{index}] {url} - {reputation}"

        lines = [first_line]
        if fontes_fora:
            lines.append(t("sources_incomplete").format(fontes=", ".join(fontes_fora)))
        lines.append(f"{t('vt_score')}: {texto_fonte(vt_score, estado_vt)}")
        if self.ibm_url_ativo:
            lines.append(f"{t('ibm_score')}: {texto_fonte(ibm_score, estado_ibm)}")
        lines.append(f"{t('alien_score')}: {texto_fonte(alien_score, estado_alien)}")
        lines.append(f"- {vt_link}")
        if self.ibm_url_ativo:
            lines.append(f"- {ibm_link}")
        lines.append(f"- {alien_link}")

        colunas = (url, t(VERDICT_KEYS[status]), "-", coluna_fonte(vt_score, estado_vt),
                   coluna_fonte(ibm_score, estado_ibm) if self.ibm_url_ativo else "-",
                   coluna_fonte(alien_score, estado_alien))
        return "\n".join(lines), status, colunas

    def process_hash(self, h, index, total_hashes=1):
        vt_link = f"https://www.virustotal.com/gui/file/{h}"
        ibm_link = f"https://exchange.xforce.ibmcloud.com/malware/{h}"
        alien_link = f"https://otx.alienvault.com/indicator/file/{h}"
        ibm_score = "-"
        alien_score = "-"
        reputation = t("no_records")
        include_ibm = self.ibm_hash_ativo
        estado_ibm = None
        malicioso = False

        # IBM
        if include_ibm:
            try:
                with self.driver_pool.emprestar() as driver:
                    _, ibm_score = check_hash_ibm(driver, h)
                estado_ibm = classificar_ibm(ibm_score)
                if estado_ibm == api.FONTE_SEM_DADOS:
                    ibm_score = t("unknown")
            except DriverIndisponivel:
                ibm_score, estado_ibm = None, api.FONTE_INDISPONIVEL

            if isinstance(ibm_score, str) and ibm_score.strip().lower() in ("high", "medium"):
                malicioso = True
                reputation = t("reputation_bad")

        # AlienVault
        alien_score, alien_link, estado_alien = check_hash_alienvault(h)
        if estado_alien == api.FONTE_OK and alien_score not in ("0", None):
            malicioso = True

        # VirusTotal
        result, estado_vt = check_hash_virustotal(h)
        if estado_vt != api.FONTE_OK or not result or "data" not in result or "attributes" not in result["data"]:
            vt_score = None
            name = "-"
            data_fmt = "N/A"
            if estado_vt == api.FONTE_OK:
                estado_vt = api.FONTE_SEM_DADOS
        else:
            attrs = result["data"]["attributes"]
            name = safe_get(attrs, "meaningful_name", default=t("unknown"))
            vt_score = safe_get(attrs, "last_analysis_stats", "malicious", default=0)
            timestamp = safe_get(attrs, "last_analysis_date")
            if timestamp:
                from datetime import datetime, timezone
                data_fmt = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%d/%m/%Y %H:%M:%S')
            else:
                data_fmt = "N/A"
            if vt_score > 0:
                malicioso = True
                reputation = t("reputation_bad")
            elif not malicioso:
                reputation = t("reputation_clean")
        # Joe Sandbox
        joe_found = False
        joe_link  = f"https://www.joesandbox.com/analysis/search?q={h}"
        try:
            with self.driver_pool.emprestar() as driver:
                joe_found, joe_link = check_hash_joesandbox(driver, h)
        except DriverIndisponivel:
            pass
        vt_texto = texto_fonte(vt_score, estado_vt)
        alien_texto = texto_fonte(alien_score, estado_alien)
        ibm_texto = texto_fonte(ibm_score, estado_ibm)

        fontes_fora = [nome for nome, estado in (
            ("VirusTotal", estado_vt), ("AlienVault", estado_alien), ("IBM X-Force", estado_ibm)
        ) if estado in api.ESTADOS_SEM_RESPOSTA]
        status = "bad" if malicioso else ("incompleto" if fontes_fora else "clean")
        if status == "incompleto":
            reputation = t("verdict_incomplete")

        if include_ibm:
            self.results_hash.append([h, vt_texto, ibm_texto, alien_texto, name, data_fmt, vt_link, ibm_link, alien_link, joe_link])
        else:
            self.results_hash.append([h, vt_texto, alien_texto, name, data_fmt, vt_link, alien_link, joe_link])
        if total_hashes == 1:
            first = f"[{h}] - {reputation}"
        else:
            first = f"[{index}] {h} - {reputation}"
        if joe_found:
            first += f" - {t('joesandbox_found')}"
        output_lines = [first]
        if fontes_fora:
            output_lines.append(t("sources_incomplete").format(fontes=", ".join(fontes_fora)))
        output_lines.append(f"{t('vt_score')}: {vt_texto}")
        if include_ibm:
            output_lines.append(f"{t('ibm_score')}: {ibm_texto}")
        output_lines.append(f"{t('alien_score')}: {alien_texto}")
        output_lines.append(f"{t('file_name')}: {name}")
        output_lines.append(f"{t('last_analysis_vt')}: {data_fmt}")
        output_lines.append(f"- {vt_link}")
        if include_ibm:
            output_lines.append(f"- {ibm_link}")
        output_lines.append(f"- {alien_link}")
        if joe_found:
            output_lines.append(f"- {joe_link}")
        colunas = (h, t(VERDICT_KEYS[status]), coluna_fonte(vt_score, estado_vt),
                   coluna_fonte(ibm_score, estado_ibm) if include_ibm else "-",
                   coluna_fonte(alien_score, estado_alien), name)
        estados = {"vt": estado_vt, "alien": estado_alien, "ibm": estado_ibm}
        return "\n".join(output_lines) + "\n", status, colunas, estados

    def cancel_check(self):
        self.stop_flag = True
        self.status_label.config(text=f"❌ {t('scan_cancelled')}")
        self.scanning_ip = False
        self.check_button.config(state="normal")
        self._update_action_buttons()
    def update_status_label(self):
        if not self.scanning_ip:
            return   # preserva a mensagem final de conclusao/cancelamento
        self.progress_ip.config(maximum=max(self.total_ip, 1), value=self.feitos_ip)
        partes = [t("progress_done").format(feitos=self.feitos_ip, total=self.total_ip)]
        if self.currently_processing:
            partes.append(f"{t('checking_ips')}: {' | '.join(sorted(self.currently_processing))}")
        self.status_label.config(text=" · ".join(partes))

    def _avancar_ip(self):
        self.feitos_ip += 1
        self.update_status_label()

    def cancel_check_hash(self):
        self.stop_flag = True
        self.hash_status_label.config(text=f"❌ {t('scan_cancelled')}")
        self.scanning_hash = False
        self.hash_button_action.config(state="normal")
        self._update_action_buttons()
    def update_status_label_hash(self):
        if not self.scanning_hash:
            return
        self.progress_hash.config(maximum=max(self.total_hash, 1), value=self.feitos_hash)
        partes = [t("progress_done").format(feitos=self.feitos_hash, total=self.total_hash)]
        if self.currently_processing_hashes:
            partes.append(f"{t('checking_hashes')}: {' | '.join(sorted(self.currently_processing_hashes))}")
        self.hash_status_label.config(text=" · ".join(partes))

    def copy_output(self):
        pyperclip.copy(self.tabela_ip.report())

    def copy_hash_output(self):
        pyperclip.copy(self.tabela_hash.report())

    def save_results(self):
        if not self.results_ip:
            messagebox.showwarning(t("done"), t("no_results"))
            return
        headers = [
            t("csv_ip"),t("csv_abuse_score"),t("csv_vt_score"),
            *( [t("csv_ibm_score")] if self.ibm_ip_ativo else [] ),
            t("csv_domain"),t("csv_country"),t("csv_city"),t("csv_last_report"),
            t("csv_abuse_link"),t("csv_vt_link"),
            *( [t("csv_ibm_link")] if self.ibm_ip_ativo else [] ),
        ]

        salvar_planilha(self.results_ip, headers, filename="ip_results.xlsx",
                    parent=self.root, titulo=t("select_folder"))

    def save_hash_results(self):
        if not self.results_hash:
            messagebox.showwarning(t("done"), t("no_results"))
            return

        headers = [
            t("csv_hash"),
            t("csv_vt_score"),
            *( [t("csv_ibm_score")] if self.ibm_hash_ativo else [] ),
            t("csv_alien_score"),
            t("csv_file_name"),
            t("csv_last_analysis"),
            t("csv_vt_link"),
            *( [t("csv_ibm_link")] if self.ibm_hash_ativo else [] ),
            t("csv_alien_link"),
            t("csv_joe_link"),
        ]   

        salvar_planilha(self.results_hash, headers, filename="hash_results.xlsx",
                    parent=self.root, titulo=t("select_folder"))

    def save_url_results(self):
        if not self.results_url:
            messagebox.showwarning(t("done"), t("no_results"))
            return
        domain_headers = [
            t("csv_domain"), t("csv_vt_score"),
            *([t("csv_ibm_score")] if self.ibm_url_ativo else []),
            t("csv_alien_score"), t("csv_vt_link"),
            *([t("csv_ibm_link")] if self.ibm_url_ativo else []),
            t("csv_alien_link"),
        ]
        ip_headers = [
            t("csv_ip"), t("csv_abuse_score"), t("csv_vt_score"),
            *([t("csv_ibm_score")] if self.ibm_url_ativo else []),
            t("csv_domain"), t("csv_country"), t("csv_city"), t("csv_last_report"),
            t("csv_abuse_link"), t("csv_vt_link"),
            *([t("csv_ibm_link")] if self.ibm_url_ativo else []),
        ]
        salvar_planilha_dominios(
            domain_results=self.results_url,
            domain_headers=domain_headers,
            ip_results_by_domain=self.ip_results_by_domain,
            ip_headers=ip_headers,
            filename="domain_results.xlsx",
            parent=self.root,
            titulo=t("select_folder"),
        )
    def run_check(self):
        if self.scanning_ip:
            messagebox.showwarning(t("done"), t("scan_already_running_ip"))
            return
        self.stop_flag = False
        self.bad_ips = set()
        self.review_ips = set()
        self.incompletos_ip = set()
        self.cota_ip = set()
        self.currently_processing.clear()
        self.status_label.config(text="")
        self.tabela_ip.clear()
        ips, ignorados = [], []
        for ip in dividir_entrada(self.entry.get_text()):
            if not is_valid_ip(ip):
                ignorados.append(f"{ip} ({t('invalid_ip')})")
            elif ipaddress.ip_address(ip).is_private:
                ignorados.append(f"{ip} ({t('private_ip')})")
            else:
                ips.append(ip)
        if not ips:
            messagebox.showerror(t("error"), t("no_valid_public_ip"))
            return
        self.ignorados_ip = ignorados
        self.results_ip = []
        self.scanning_ip = True
        self.ibm_ip_ativo = self.ibm_var_ip.get()
        self.total_ip, self.feitos_ip = len(ips), 0
        self.check_button.config(state="disabled")
        self._update_action_buttons()
        self.update_status_label()
        Thread(target=self._check_ips_thread, args=(ips,), daemon=True).start()

    def _check_ips_thread(self, ips):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        def process_ip(index, ip):
            if self.stop_flag:
                return None
            self._track_processing(self.currently_processing, ip, True, self.update_status_label)
            if self.stop_flag:
                return None
            abuseipdb_result, estado_abuse = check_ip_abuseipdb(ip)
            if self.stop_flag:
                return None
            virustotal_result, estado_vt = check_ip_virustotal(ip)
            if self.stop_flag:
                return None
            city, country = get_location(ip)
            domain = get_domain_from_abuseipdb(abuseipdb_result)
            ibm_score, estado_ibm = None, api.FONTE_OK
            if self.ibm_ip_ativo and not self.stop_flag:
                try:
                    with self.driver_pool.emprestar() as driver:
                        _, ibm_score = check_ip_ibm(driver, ip)
                    estado_ibm = classificar_ibm(ibm_score)
                    if estado_ibm == api.FONTE_SEM_DADOS:
                        ibm_score = t("unknown")
                except DriverIndisponivel:
                    ibm_score, estado_ibm = None, api.FONTE_INDISPONIVEL
            if self.stop_flag:
                return None
            data = build_ip_result(
                ip=ip,
                abuseipdb_result=abuseipdb_result,
                virustotal_result=virustotal_result,
                ibm_score=ibm_score,
                city=city,
                country=country,
                domain=domain,
                estado_abuse=estado_abuse,
                estado_vt=estado_vt,
                estado_ibm=estado_ibm,
            )
            terminal_output = relatorio_ip(data, index=index, total=len(ips))
            csv_data = linha_planilha_ip(data, self.ibm_ip_ativo)
            colunas = colunas_ip(data, data["country"] or "-")
            return (index, csv_data, terminal_output, ip, data["status"], colunas, data)
        try:
            # Os IPs terminam fora de ordem; so vai para a tela o trecho ja em sequencia,
            # para a saida crescer sem redesenhar o que ja esta la.
            pendentes = {}
            proximo = 1
            with ThreadPoolExecutor(max_workers=min(len(ips), 10)) as executor:
                futures = {executor.submit(process_ip, i + 1, ip): i for i, ip in enumerate(ips)}
                for future in as_completed(futures):
                    if self.stop_flag:
                        for f in futures:
                            f.cancel()
                        break
                    try:
                        result = future.result(timeout=1)
                    except Exception as e:
                        if not self.stop_flag:
                            indice = futures[future]
                            self._ui(self._linha_erro_ip, indice, ips[indice], str(e))
                        continue
                    if not result:
                        continue
                    self._track_processing(self.currently_processing, result[3], False,
                                           self.update_status_label)
                    self._ui(self._avancar_ip)
                    pendentes[result[0]] = result
                    prontos = []
                    while proximo in pendentes:
                        prontos.append(pendentes.pop(proximo))
                        proximo += 1
                    if prontos:
                        self._ui(self.append_ip_results, prontos)
            if not self.stop_flag:
                # Sobra o que ficou preso atras de um indice que nunca chegou.
                restantes = [pendentes[chave] for chave in sorted(pendentes)]
                if restantes:
                    self._ui(self.append_ip_results, restantes)
                self._ui(self._finish_ip_scan)
        finally:
            self.scanning_ip = False
            self._ui(self._scan_stopped_ip)

    def append_ip_results(self, resultados):
        for index, csv_data, terminal_output, ip, status, colunas, data in resultados:
            if status == "bad":
                self.bad_ips.add(ip)
            elif status == "whitelisted_bad":
                self.review_ips.add(ip)
            elif status == "incompleto":
                self.incompletos_ip.add(ip)
            self.cota_ip.update(fontes_em_cota(data.get("estados", {})))
            self.results_ip.append(csv_data)
            self.tabela_ip.add(f"ip-{index}", colunas, terminal_output, status)
        self._update_action_buttons()

    def _linha_erro_ip(self, indice, ip, erro):
        self.tabela_ip.add(f"ip-erro-{indice}",
                           (ip, t("verdict_unknown"), "-", "-", "-", "-"),
                           f"{ip}\n{t('error_processing_ip')}: {erro}", "unknown")
        self._avancar_ip()
        self._update_action_buttons()

    def _finish_ip_scan(self):
        self._append_analysis()
        self.progress_ip.config(value=self.total_ip)
        self.status_label.config(text=f"✅ {t('scan_finished')}")

    def _scan_stopped_ip(self):
        self.check_button.config(state="normal")
        self._update_action_buttons()

    def _append_analysis(self):
        blocos = []
        if self.cota_ip:
            blocos.append(t("quota_warning").format(fontes=", ".join(sorted(self.cota_ip))))
        if self.ignorados_ip:
            blocos.append(f"{t('skipped_items')}: {', '.join(self.ignorados_ip)}")
        if self.incompletos_ip:
            blocos.append(t("incomplete_review").format(lista=", ".join(sorted(self.incompletos_ip))))
        if not self.pre_var_ip.get():
            self.tabela_ip.set_preamble("\n\n".join(blocos))
            return
        if self.bad_ips:
            chave = "ip_bad_mss" if self.mss_var_ip.get() else "ip_bad_no_mss"
            blocos.append(plural(chave, self.bad_ips))
        if self.review_ips:
            blocos.append(plural("ip_whitelist_review", self.review_ips))
        # "Nada malicioso encontrado" so vale se todas as fontes responderam.
        if not self.bad_ips and not self.review_ips and not self.incompletos_ip:
            blocos.append(plural("ip_clean", self.results_ip))
        self.tabela_ip.set_preamble("\n\n".join(blocos))

    def process_url_ip_associated(self, ip, domain):
        try:
            abuseipdb_result, estado_abuse = check_ip_abuseipdb(ip)
            virustotal_result, estado_vt = check_ip_virustotal(ip)
            city, country = get_location(ip)
            assoc_domain = get_domain_from_abuseipdb(abuseipdb_result)
            ibm_score, estado_ibm = None, api.FONTE_OK
            if self.ibm_url_ativo:
                try:
                    with self.driver_pool.emprestar() as driver:
                        _, ibm_score = check_ip_ibm(driver, ip)
                    estado_ibm = classificar_ibm(ibm_score)
                    if estado_ibm == api.FONTE_SEM_DADOS:
                        ibm_score = t("unknown")
                except DriverIndisponivel:
                    ibm_score, estado_ibm = None, api.FONTE_INDISPONIVEL
            data = build_ip_result(
                ip=ip,
                abuseipdb_result=abuseipdb_result,
                virustotal_result=virustotal_result,
                ibm_score=ibm_score,
                city=city,
                country=country,
                domain=assoc_domain,
                estado_abuse=estado_abuse,
                estado_vt=estado_vt,
                estado_ibm=estado_ibm,
            )
            return (relatorio_ip(data), data["status"],
                    linha_planilha_ip(data, self.ibm_url_ativo), colunas_ip(data, "-"),
                    data.get("estados", {}))
        except Exception as e:
            erro = f"{t('error_checking_associated_ip')} {ip}: {e}"
            return erro, "unknown", None, (ip, t("verdict_unknown"), "-", "-", "-", "-"), {}

    # helpers de resolução de domínio p/ IP
    @staticmethod
    def _is_public_ip(ip: str) -> bool:
        try:
            return ipaddress.ip_address(ip).is_global
        except ValueError:
            return False

    @staticmethod
    def _resolve_domain_via_google_dns(domain: str):
        """Usa o serviço público https://dns.google/resolve
        Retorna lista de IPs v4/v6 públicos ou [] em erro. """
        try:
            resp = requests.get(
                f"https://dns.google/resolve?name={domain}&type=A", timeout=5)
            data = resp.json()
            ips = []
            for answer in data.get("Answer", []):
                ip = answer.get("data")
                if ip and IPCheckerApp._is_public_ip(ip):
                    ips.append(ip)
            return ips
        except Exception:
            return []

    @staticmethod
    def _resolve_domain_with_socket(domain: str):
        try:
            _name, _alias, ips = socket.gethostbyname_ex(domain)
            return [ip for ip in ips if IPCheckerApp._is_public_ip(ip)]
        except Exception:
            return []

    def on_close(self):
        try:
            self.driver_pool.encerrar()
        except Exception as e:
            print(f"Erro ao fechar drivers: {e}")
        finally:
            self.root.destroy()
