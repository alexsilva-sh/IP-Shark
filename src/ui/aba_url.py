"""Aba de dominios: montagem da tela, varredura, IPs resolvidos e exportacao."""
import ipaddress
import socket
import tkinter as tk
from threading import Thread
from tkinter import messagebox, ttk

import pyperclip
import requests

from core import api
from core.api import (
    check_ip_abuseipdb,
    check_ip_virustotal,
    check_url_alienvault,
    check_url_virustotal,
    get_location,
)
from core.navegador import check_ip_ibm, check_url_ibm
from core.reputacao import (
    build_ip_result,
    build_url_result,
    dominio_valido,
    extrair_dominio,
    get_domain_from_abuseipdb,
)
from i18n import plural, t
from services.exportacao import salvar_planilha_dominios
from ui import tema
from ui.apresentacao import (
    aviso_de_cota,
    colunas_ip,
    colunas_url,
    contar_dominios,
    dividir_entrada,
    fontes_em_cota,
    linha_planilha_ip,
    linha_planilha_url,
    relatorio_ip,
    relatorio_url,
)
from ui.widgets import MultilineInput, ResultTable, ToggleSwitch


def _ip_publico(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def resolver_via_google_dns(dominio):
    """Usa o serviço público https://dns.google/resolve.
    Retorna lista de IPs v4/v6 públicos ou [] em erro."""
    try:
        resposta = requests.get(f"https://dns.google/resolve?name={dominio}&type=A", timeout=5)
        return [registro.get("data") for registro in resposta.json().get("Answer", [])
                if _ip_publico(registro.get("data"))]
    except Exception:
        return []


def resolver_via_socket(dominio):
    try:
        _nome, _apelidos, ips = socket.gethostbyname_ex(dominio)
        return [ip for ip in ips if _ip_publico(ip)]
    except Exception:
        return []


class AbaURL:
    """Mixin de IPCheckerApp. Usa a infraestrutura compartilhada da janela principal:
    _ui, _track_processing, _consultar_ibm, _update_action_buttons e stop_flag."""

    def _montar_aba_url(self):
        self.ibm_url_ativo = True
        self.check_ips_url_ativo = True
        self.results_url = []
        self.scanning_url = False
        self.currently_processing_urls = set()
        self.bad_urls = set()
        self.review_urls = set()
        self.incompletos_url = set()
        self.cota_url = set()
        self.ignorados_url = []
        self.ip_results_by_domain = {}
        self.total_url = self.feitos_url = 0

        self.url_button = ttk.Button(self.tab_frame, text=t("tab_domain"),
                                     command=self.show_url_page, style="Nav.TButton")
        self.url_button.grid(row=0, column=2, padx=5)
        self._register_i18n(self.url_button, "tab_domain")
        self.page_url = tk.Frame(self.root, bg=tema.FUNDO)

        self.input_label_url = ttk.Label(self.page_url, text=t("paste_domains"),
                                         style="Title.TLabel")
        self.input_label_url.pack(pady=(10, 2))
        self._register_i18n(self.input_label_url, "paste_domains")
        self.url_entry = MultilineInput(self.page_url, contar_dominios)
        self.url_entry.pack(pady=6, padx=20, fill="x")

        toggles = tk.Frame(self.page_url, bg=tema.FUNDO)
        toggles.pack(pady=6)
        self.ibm_var_url = tk.BooleanVar(value=True)
        self.toggle_ibm_url = ToggleSwitch(toggles, text=t("toggle_ibm"), variable=self.ibm_var_url)
        self.toggle_ibm_url.pack(side="left", padx=(0, 15))
        self._register_i18n(self.toggle_ibm_url.label, "toggle_ibm")
        self.check_ips_var_url = tk.BooleanVar(value=True)
        self.toggle_check_ips = ToggleSwitch(toggles, text=t("toggle_check_ips"),
                                             variable=self.check_ips_var_url)
        self.toggle_check_ips.pack(side="left", padx=(0, 15))
        self._register_i18n(self.toggle_check_ips.label, "toggle_check_ips")
        coluna = tk.Frame(toggles, bg=tema.FUNDO)
        coluna.pack(side="left")
        self.pre_var_url = tk.BooleanVar(value=False)
        self.toggle_pre_url = ToggleSwitch(coluna, text=t("toggle_pre_analysis"),
                                           variable=self.pre_var_url)
        self.toggle_pre_url.pack(anchor="w")
        self._register_i18n(self.toggle_pre_url.label, "toggle_pre_analysis")
        self.mss_var_url = tk.BooleanVar(value=False)
        self.mss_url_switch = ToggleSwitch(coluna, text=t("toggle_has_mss"),
                                           variable=self.mss_var_url, state="disabled")
        self.mss_url_switch.pack(anchor="w")
        self._register_i18n(self.mss_url_switch.label, "toggle_has_mss")
        self.pre_var_url.trace_add("write", self._update_mss_state_url)

        self.url_button_action = ttk.Button(self.page_url, text=t("btn_check_domain"),
                                            command=self.run_url_check, style="Primary.TButton")
        self.url_button_action.pack(pady=12)
        self._register_i18n(self.url_button_action, "btn_check_domain")
        self.progress_url, self.url_status_label = self._montar_progresso(self.page_url)

        self.url_button_frame = tk.Frame(self.page_url, bg=tema.FUNDO)
        self.url_button_frame.pack(side=tk.BOTTOM, pady=10, fill=tk.X)
        self.url_button_frame.grid_columnconfigure(0, weight=1)
        self.url_button_frame.grid_columnconfigure(4, weight=1)

        self.tabela_url = ResultTable(self.page_url, [
            ("#0", "csv_domain", 260, "w"),
            ("veredito", "col_verdict", 160, "w"),
            ("abuse", "col_abuse", 95, "center"),
            ("vt", "col_vt", 95, "center"),
            ("ibm", "col_ibm", 85, "center"),
            ("alien", "col_alien", 95, "center"),
        ])
        self.tabela_url.pack(padx=10, pady=(0, 5), fill=tk.BOTH, expand=True)

        self.url_copy_button = ttk.Button(self.url_button_frame, text=t("btn_copy"),
                                          command=self.copy_url_output, style="Secondary.TButton")
        self.url_copy_button.grid(row=0, column=1, padx=10)
        self._register_i18n(self.url_copy_button, "btn_copy")
        self.url_save_button = ttk.Button(self.url_button_frame, text=t("btn_export"),
                                          command=self.save_url_results, style="Secondary.TButton")
        self.url_save_button.grid(row=0, column=2, padx=10)
        self._register_i18n(self.url_save_button, "btn_export")
        self.url_cancel_button = ttk.Button(self.url_button_frame, text=t("btn_cancel"),
                                            command=self.cancel_check_url, style="Danger.TButton")
        self.url_cancel_button.grid(row=0, column=3, padx=10)
        self._register_i18n(self.url_cancel_button, "btn_cancel")

    def show_url_page(self):
        self._mostrar_pagina("url")

    def _update_mss_state_url(self, *args):
        self.mss_url_switch.set_state("normal" if self.pre_var_url.get() else "disabled")

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
        bruto_list = dividir_entrada(self.url_entry.get_text())
        if not bruto_list:
            messagebox.showerror(t("error"), t("no_domain"))
            return
        # Normaliza e valida antes de gastar vaga do pool de Chrome e cota de API.
        url_list, ignorados = [], []
        for bruto in bruto_list:
            dominio = extrair_dominio(bruto)
            if dominio_valido(dominio):
                url_list.append(dominio)
            else:
                ignorados.append(f"{bruto} ({t('invalid_domain')})")
        if not url_list:
            messagebox.showerror(t("error"), t("no_valid_domain"))
            return
        self.ignorados_url = ignorados
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
        Thread(target=self._check_urls_thread, args=(url_list,), daemon=True).start()

    def _check_urls_thread(self, url_list):
        try:
            for i, url in enumerate(url_list):
                if self.stop_flag:
                    break
                self._track_processing(self.currently_processing_urls, url, True,
                                       self.update_status_label_url)
                data = self._consultar_dominio(url)
                if data is None:
                    break
                status = data["status"]
                if status == "bad":
                    self.bad_urls.add(url)
                elif status == "incompleto":
                    self.incompletos_url.add(url)
                self.cota_url.update(fontes_em_cota(data["estados"]))
                self._track_processing(self.currently_processing_urls, url, False,
                                       self.update_status_label_url)
                self.results_url.append(linha_planilha_url(data, self.ibm_url_ativo))
                self._ui(self._linha_url, i + 1,
                         colunas_url(data, self.ibm_url_ativo),
                         relatorio_url(data, self.ibm_url_ativo, index=i + 1, total=len(url_list)),
                         status)
                if self.check_ips_url_ativo and not self.stop_flag:
                    self._varrer_ips_do_dominio(i + 1, url)
            if not self.stop_flag:
                self._ui(self._finish_url_scan)
        finally:
            self.scanning_url = False
            self._ui(self._scan_stopped_url)

    def _consultar_dominio(self, url):
        """Veredito do dominio, ou None se a varredura foi cancelada no meio."""
        if self.stop_flag:
            return None
        result_vt, estado_vt = check_url_virustotal(url)
        if self.stop_flag:
            return None
        ibm_score, estado_ibm = "-", None
        if self.ibm_url_ativo and not self.stop_flag:
            ibm_score, estado_ibm = self._consultar_ibm(check_url_ibm, url)
        if self.stop_flag:
            return None
        alien_score, _alien_link, estado_alien = check_url_alienvault(url)
        return build_url_result(url, result_vt.get("score"), ibm_score, alien_score,
                                estado_vt=estado_vt, estado_ibm=estado_ibm,
                                estado_alien=estado_alien)

    def _varrer_ips_do_dominio(self, indice, domain):
        ips = resolver_via_google_dns(domain) or resolver_via_socket(domain)
        ips = sorted(set(ips))
        self.ip_results_by_domain[domain] = []
        if not ips:
            self._ui(self._linha_url_filha, indice, 0,
                     (t("domain_no_ip"), t("verdict_unknown"), "-", "-", "-", "-"),
                     f"[{domain}] {t('domain_no_ip')}", "unknown")
            return
        for j, ip in enumerate(ips, 1):
            if self.stop_flag:
                break
            texto, status, csv_data, colunas, estados = self.process_url_ip_associated(ip, domain)
            self._ui(self._linha_url_filha, indice, j, colunas, texto.lstrip("\n"), status)
            self.cota_url.update(fontes_em_cota(estados))
            if status == "bad":
                self.bad_urls.add(f"{ip} ({t('associated_to_domain')} {domain})")
            if status == "whitelisted_bad":
                self.review_urls.add(ip)
            if status in ("incompleto", "unknown"):
                self.incompletos_url.add(ip)
            if csv_data:
                self.ip_results_by_domain[domain].append(csv_data)

    def process_url_ip_associated(self, ip, domain):
        try:
            abuseipdb_result, estado_abuse = check_ip_abuseipdb(ip)
            virustotal_result, estado_vt = check_ip_virustotal(ip)
            city, country = get_location(ip)
            assoc_domain = get_domain_from_abuseipdb(abuseipdb_result)
            ibm_score, estado_ibm = None, api.FONTE_OK
            if self.ibm_url_ativo:
                ibm_score, estado_ibm = self._consultar_ibm(
                    lambda d, alvo: check_ip_ibm(d, alvo)[1], ip)
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
            blocos.append(aviso_de_cota(self.cota_url))
        if self.ignorados_url:
            blocos.append(f"{t('skipped_items')}: {', '.join(self.ignorados_url)}")
        if self.incompletos_url:
            blocos.append(t("incomplete_review").format(
                lista=", ".join(sorted(self.incompletos_url))))
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
            partes.append(f"{t('checking_domains')}: "
                          f"{' | '.join(sorted(self.currently_processing_urls))}")
        self.url_status_label.config(text=" · ".join(partes))

    def cancel_check_url(self):
        self.stop_flag = True
        self.url_status_label.config(text=f"❌ {t('scan_cancelled')}")
        self.scanning_url = False
        self.url_button_action.config(state="normal")
        self._update_action_buttons()

    def copy_url_output(self):
        pyperclip.copy(self.tabela_url.report())

    def save_url_results(self):
        if not self.results_url:
            messagebox.showwarning(t("done"), t("no_results"))
            return
        domain_headers = [
            t("csv_domain"), t("csv_verdict"), t("csv_vt_score"),
            *([t("csv_ibm_score")] if self.ibm_url_ativo else []),
            t("csv_alien_score"), t("csv_vt_link"),
            *([t("csv_ibm_link")] if self.ibm_url_ativo else []),
            t("csv_alien_link"),
        ]
        ip_headers = [
            t("csv_ip"), t("csv_verdict"), t("csv_abuse_score"), t("csv_vt_score"),
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
            coluna_veredito=2,
            aba=t("csv_sheet_domains"),
            prefixo_aba_ips=t("csv_sheet_ips_prefix"),
        )
