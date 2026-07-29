"""Aba de hashes: montagem da tela, varredura e exportacao."""
import re
import tkinter as tk
from threading import Thread
from tkinter import messagebox, ttk

import pyperclip

from core.api import check_hash_alienvault, check_hash_virustotal
from core.navegador import check_hash_ibm, check_hash_joesandbox
from core.reputacao import build_hash_result
from i18n import plural, t
from services.exportacao import salvar_planilha
from ui import tema
from ui.apresentacao import (
    aviso_de_cota,
    colunas_hash,
    contar_hashes,
    dividir_entrada,
    fontes_em_cota,
    linha_planilha_hash,
    relatorio_hash,
)
from ui.navegadores import DriverIndisponivel
from ui.widgets import Chip


class AbaHash:
    """Mixin de IPCheckerApp. Usa a infraestrutura compartilhada da janela principal:
    _ui, _track_processing, _consultar_ibm, _update_action_buttons e stop_flag."""

    def _montar_aba_hash(self):
        self.ibm_hash_ativo = True
        self.results_hash = []
        self.scanning_hash = False
        self.currently_processing_hashes = set()
        self.bad_hashes = set()
        self.ignorados_hash = []
        self.incompletos_hash = set()
        self.cota_hash = set()
        self.total_hash = self.feitos_hash = 0

        self.hash_button = ttk.Button(self.tab_frame, text=t("tab_hash"),
                                      command=self.show_hash_page, style="Nav.TButton")
        self.hash_button.pack(fill="x", pady=(0, tema.E1))
        self._register_i18n(self.hash_button, "tab_hash")
        self.page_hash = tk.Frame(self.area_conteudo, bg=tema.FUNDO)

        self.input_label_hash, self.hash_entry = self._montar_entrada(
            self.page_hash, "paste_hashes", contar_hashes)
        self.hash_button_action, fontes, relatorio = self._montar_opcoes(
            self.page_hash, "btn_check_hash", self.run_hash_check)

        self.ibm_var_hash = tk.BooleanVar(value=True)
        self.toggle_ibm_hash = Chip(fontes, text=t("toggle_ibm"), variable=self.ibm_var_hash)
        self.toggle_ibm_hash.pack(side="left")
        self._register_i18n(self.toggle_ibm_hash, "toggle_ibm")

        self.pre_var_hash = tk.BooleanVar(value=False)
        self.toggle_pre_hash = Chip(relatorio, text=t("toggle_pre_analysis"),
                                    variable=self.pre_var_hash,
                                    ao_mudar=self._update_mss_state_hash)
        self.toggle_pre_hash.pack(side="left")
        self._register_i18n(self.toggle_pre_hash, "toggle_pre_analysis")
        self.mss_var_hash = tk.BooleanVar(value=False)
        self.mss_hash_switch = Chip(relatorio, text=t("toggle_has_mss"),
                                    variable=self.mss_var_hash, state="disabled")
        self.mss_hash_switch.pack(side="left", padx=(tema.E2, 0))
        self._register_i18n(self.mss_hash_switch, "toggle_has_mss")
        self.pre_var_hash.trace_add("write", self._update_mss_state_hash)

        self.hash_button_frame = tk.Frame(self.page_hash, bg=tema.FUNDO)
        self.hash_button_frame.pack(side=tk.BOTTOM, pady=tema.E3, fill=tk.X)
        self.hash_button_frame.grid_columnconfigure(0, weight=1)
        self.hash_button_frame.grid_columnconfigure(4, weight=1)

        self.tabela_hash, self.progress_hash, self.hash_status_label = self._montar_resultados(
            self.page_hash, [
            ("#0", "csv_hash", 250, "w"),
            ("veredito", "col_verdict", 175, "w"),
            ("arquivo", "col_file", 250, "w"),
            ("vt", "col_vt", 95, "center"),
            ("ibm", "col_ibm", 85, "center"),
            ("alien", "col_alien", 110, "center"),
        ])

        self.hash_copy_button = ttk.Button(self.hash_button_frame, text=t("btn_copy"),
                                           command=self.copy_hash_output, style="Secondary.TButton")
        self.hash_copy_button.grid(row=0, column=1, padx=tema.E2)
        self._register_i18n(self.hash_copy_button, "btn_copy")
        self.hash_save_button = ttk.Button(self.hash_button_frame, text=t("btn_export"),
                                           command=self.save_hash_results, style="Secondary.TButton")
        self.hash_save_button.grid(row=0, column=2, padx=tema.E2)
        self._register_i18n(self.hash_save_button, "btn_export")
        self.hash_cancel_button = ttk.Button(self.hash_button_frame, text=t("btn_cancel"),
                                             command=self.cancel_check_hash, style="Danger.TButton")
        self.hash_cancel_button.grid(row=0, column=3, padx=tema.E2)
        self._register_i18n(self.hash_cancel_button, "btn_cancel")

    def show_hash_page(self):
        self._mostrar_pagina("hash")

    def _update_mss_state_hash(self, *args):
        self.mss_hash_switch.set_state("normal" if self.pre_var_hash.get() else "disabled")

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
        self.registrar_historico("hash", self.hash_entry.get_text(), len(hash_list))
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
        Thread(target=self._check_hashes_thread, args=(hash_list,), daemon=True).start()

    def _check_hashes_thread(self, hash_list):
        try:
            for i, h in enumerate(hash_list):
                if self.stop_flag:
                    break
                self._track_processing(self.currently_processing_hashes, h, True,
                                       self.update_status_label_hash)
                texto, status, colunas, estados = self.process_hash(h, i + 1,
                                                                    total_hashes=len(hash_list))
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

    def process_hash(self, h, index, total_hashes=1):
        com_ibm = self.ibm_hash_ativo
        ibm_score, estado_ibm = "-", None
        if com_ibm:
            ibm_score, estado_ibm = self._consultar_ibm(
                lambda d, alvo: check_hash_ibm(d, alvo)[1], h)

        alien_score, _alien_link, estado_alien = check_hash_alienvault(h)
        virustotal_result, estado_vt = check_hash_virustotal(h)

        joe_found = False
        try:
            with self.driver_pool.emprestar() as driver:
                joe_found, _joe_link = check_hash_joesandbox(driver, h)
        except DriverIndisponivel:
            pass

        data = build_hash_result(h, virustotal_result, ibm_score, alien_score, joe_found,
                                 estado_vt=estado_vt, estado_ibm=estado_ibm,
                                 estado_alien=estado_alien)
        self.results_hash.append(linha_planilha_hash(data, com_ibm))
        return (relatorio_hash(data, com_ibm, index=index, total=total_hashes),
                data["status"], colunas_hash(data, com_ibm), data["estados"])

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
            blocos.append(aviso_de_cota(self.cota_hash))
        if self.ignorados_hash:
            blocos.append(f"{t('skipped_items')}: {', '.join(self.ignorados_hash)}")
        if self.incompletos_hash:
            blocos.append(t("incomplete_review").format(
                lista=", ".join(sorted(self.incompletos_hash))))
        if self.pre_var_hash.get():
            if self.bad_hashes:
                chave = "hash_bad_mss" if self.mss_var_hash.get() else "hash_bad_no_mss"
                blocos.append(plural(chave, self.bad_hashes))
            elif not self.incompletos_hash:
                blocos.append(plural("hash_clean", self.results_hash))
        self.tabela_hash.set_preamble("\n\n".join(blocos))

    def update_status_label_hash(self):
        if not self.scanning_hash:
            return
        self.progress_hash.config(maximum=max(self.total_hash, 1), value=self.feitos_hash)
        partes = [t("progress_done").format(feitos=self.feitos_hash, total=self.total_hash)]
        if self.currently_processing_hashes:
            partes.append(f"{t('checking_hashes')}: "
                          f"{' | '.join(sorted(self.currently_processing_hashes))}")
        self.hash_status_label.config(text=" · ".join(partes))

    def cancel_check_hash(self):
        self.stop_flag = True
        self.hash_status_label.config(text=f"❌ {t('scan_cancelled')}")
        self.scanning_hash = False
        self.hash_button_action.config(state="normal")
        self._update_action_buttons()

    def copy_hash_output(self):
        pyperclip.copy(self.tabela_hash.report())

    def save_hash_results(self):
        if not self.results_hash:
            messagebox.showwarning(t("done"), t("no_results"))
            return
        headers = [
            t("csv_hash"), t("csv_verdict"), t("csv_vt_score"),
            *([t("csv_ibm_score")] if self.ibm_hash_ativo else []),
            t("csv_alien_score"), t("csv_file_name"), t("csv_last_analysis"), t("csv_vt_link"),
            *([t("csv_ibm_link")] if self.ibm_hash_ativo else []),
            t("csv_alien_link"), t("csv_joe_link"),
        ]
        salvar_planilha(self.results_hash, headers, filename="hash_results.xlsx",
                        parent=self.root, titulo=t("select_folder"), coluna_veredito=2,
                        aba=t("csv_sheet_results"))
