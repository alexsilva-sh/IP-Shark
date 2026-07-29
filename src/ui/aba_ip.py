"""Aba de IPs: montagem da tela, varredura paralela e exportacao."""
import ipaddress
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Thread
from tkinter import messagebox, ttk

import pyperclip

import log
from core import api
from core.api import check_ip_abuseipdb, check_ip_virustotal, get_location
from core.navegador import check_ip_ibm
from core.reputacao import build_ip_result, get_domain_from_abuseipdb, is_valid_ip
from i18n import plural, t
from services.exportacao import salvar_planilha
from ui import tema
from ui.apresentacao import (
    aviso_de_cota,
    colunas_ip,
    contar_ips,
    dividir_entrada,
    fontes_em_cota,
    linha_planilha_ip,
    relatorio_ip,
)
from ui.widgets import MultilineInput, ResultTable, ToggleSwitch

_log = log.obter("aba_ip")


class AbaIP:
    """Mixin de IPCheckerApp. Usa a infraestrutura compartilhada da janela principal:
    _ui, _track_processing, _consultar_ibm, _update_action_buttons e stop_flag."""

    def _montar_aba_ip(self):
        self.ibm_ip_ativo = True
        self.results_ip = []
        self.scanning_ip = False
        self.currently_processing = set()
        self.bad_ips = set()
        self.review_ips = set()
        self.ignorados_ip = []
        self.incompletos_ip = set()
        self.cota_ip = set()
        self.total_ip = self.feitos_ip = 0

        self.ip_button = ttk.Button(self.tab_frame, text=t("tab_ip"),
                                    command=self.show_ip_page, style="NavActive.TButton")
        self.ip_button.grid(row=0, column=0, padx=5)
        self._register_i18n(self.ip_button, "tab_ip")
        self.page_ip = tk.Frame(self.root, bg=tema.FUNDO)

        self.input_label = ttk.Label(self.page_ip, text=t("paste_ips"), style="Title.TLabel")
        self.input_label.pack(pady=(10, 2))
        self._register_i18n(self.input_label, "paste_ips")
        self.entry = MultilineInput(self.page_ip, contar_ips)
        self.entry.pack(pady=6, padx=20, fill="x")

        toggles = tk.Frame(self.page_ip, bg=tema.FUNDO)
        toggles.pack(pady=6)
        self.ibm_var_ip = tk.BooleanVar(value=True)
        self.toggle_ibm_ip = ToggleSwitch(toggles, text=t("toggle_ibm"), variable=self.ibm_var_ip)
        self.toggle_ibm_ip.pack(side="left", padx=(0, 15))
        self._register_i18n(self.toggle_ibm_ip.label, "toggle_ibm")
        coluna = tk.Frame(toggles, bg=tema.FUNDO)
        coluna.pack(side="left")
        self.pre_var_ip = tk.BooleanVar(value=False)
        self.toggle_pre_ip = ToggleSwitch(coluna, text=t("toggle_pre_analysis"),
                                          variable=self.pre_var_ip)
        self.toggle_pre_ip.pack(anchor="w")
        self._register_i18n(self.toggle_pre_ip.label, "toggle_pre_analysis")
        self.mss_var_ip = tk.BooleanVar(value=False)
        self.mss_ip_switch = ToggleSwitch(coluna, text=t("toggle_has_mss"),
                                          variable=self.mss_var_ip, state="disabled")
        self.mss_ip_switch.pack(anchor="w")
        self._register_i18n(self.mss_ip_switch.label, "toggle_has_mss")
        self.pre_var_ip.trace_add("write", self._update_mss_state_ip)

        self.check_button = ttk.Button(self.page_ip, text=t("btn_check_ip"),
                                       command=self.run_check, style="Primary.TButton")
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

        self.copy_button = ttk.Button(self.button_frame, text=t("btn_copy"),
                                      command=self.copy_output, style="Secondary.TButton")
        self.copy_button.grid(row=0, column=1, padx=10)
        self._register_i18n(self.copy_button, "btn_copy")
        self.save_button = ttk.Button(self.button_frame, text=t("btn_export"),
                                      command=self.save_results, style="Secondary.TButton")
        self.save_button.grid(row=0, column=2, padx=10)
        self._register_i18n(self.save_button, "btn_export")
        self.cancel_button = ttk.Button(self.button_frame, text=t("btn_cancel"),
                                        command=self.cancel_check, style="Danger.TButton")
        self.cancel_button.grid(row=0, column=3, padx=10)
        self._register_i18n(self.cancel_button, "btn_cancel")

    def show_ip_page(self):
        self._mostrar_pagina("ip")

    def _update_mss_state_ip(self, *args):
        self.mss_ip_switch.set_state("normal" if self.pre_var_ip.get() else "disabled")

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
        try:
            # Os IPs terminam fora de ordem; so vai para a tela o trecho ja em sequencia,
            # para a saida crescer sem redesenhar o que ja esta la.
            pendentes = {}
            proximo = 1
            with ThreadPoolExecutor(max_workers=min(len(ips), 10)) as executor:
                futures = {executor.submit(self._consultar_ip, i + 1, ip, len(ips)): i
                           for i, ip in enumerate(ips)}
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
                            # O IP vai para a tela, nao para o arquivo de registro.
                            _log.exception("falha ao consultar um IP da lista")
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

    def _consultar_ip(self, index, ip, total):
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
            ibm_score, estado_ibm = self._consultar_ibm(lambda d, alvo: check_ip_ibm(d, alvo)[1], ip)
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
        return (index, linha_planilha_ip(data, self.ibm_ip_ativo),
                relatorio_ip(data, index=index, total=total), ip, data["status"],
                colunas_ip(data, data["country"] or "-"), data)

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

    def _avancar_ip(self):
        self.feitos_ip += 1
        self.update_status_label()

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
            blocos.append(aviso_de_cota(self.cota_ip))
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

    def update_status_label(self):
        if not self.scanning_ip:
            return   # preserva a mensagem final de conclusao/cancelamento
        self.progress_ip.config(maximum=max(self.total_ip, 1), value=self.feitos_ip)
        partes = [t("progress_done").format(feitos=self.feitos_ip, total=self.total_ip)]
        if self.currently_processing:
            partes.append(f"{t('checking_ips')}: {' | '.join(sorted(self.currently_processing))}")
        self.status_label.config(text=" · ".join(partes))

    def cancel_check(self):
        self.stop_flag = True
        self.status_label.config(text=f"❌ {t('scan_cancelled')}")
        self.scanning_ip = False
        self.check_button.config(state="normal")
        self._update_action_buttons()

    def copy_output(self):
        pyperclip.copy(self.tabela_ip.report())

    def save_results(self):
        if not self.results_ip:
            messagebox.showwarning(t("done"), t("no_results"))
            return
        headers = [
            t("csv_ip"), t("csv_verdict"), t("csv_abuse_score"), t("csv_vt_score"),
            *([t("csv_ibm_score")] if self.ibm_ip_ativo else []),
            t("csv_domain"), t("csv_country"), t("csv_city"), t("csv_last_report"),
            t("csv_abuse_link"), t("csv_vt_link"),
            *([t("csv_ibm_link")] if self.ibm_ip_ativo else []),
        ]
        salvar_planilha(self.results_ip, headers, filename="ip_results.xlsx",
                        parent=self.root, titulo=t("select_folder"), coluna_veredito=2,
                        aba=t("csv_sheet_results"))
