"""Janela de cadastro das chaves de API."""
import os
import sys
import tkinter as tk
import webbrowser
from threading import Thread
from tkinter import messagebox, ttk

import log
from core import api
from core.api import carregar_chaves_salvas, reload_api_keys, salvar_chaves
from i18n import t
from services import cofre
from ui import tema

_log = log.obter("config")


def _diretorio_base():
    if getattr(sys, "frozen", False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class ConfigAPIDialog(tk.Toplevel):
    LARGURA_CAMPO = 46

    def __init__(self, master):
        super().__init__(master)
        self.title(t("cfg_title"))
        self.configure(bg=tema.FUNDO)
        self.resizable(False, False)
        self.transient(master)

        salvas = carregar_chaves_salvas()
        self.campos = {}
        self.revelado = {}

        corpo = tk.Frame(self, bg=tema.FUNDO, padx=22, pady=18)
        corpo.pack(fill="both", expand=True)

        ttk.Label(corpo, text=t("cfg_title"), style="Title.TLabel").pack(anchor="w")

        cifrado = cofre.criptografia_disponivel()
        aviso = t("cfg_intro") if cifrado else t("cfg_intro_sem_cripto")
        tk.Label(corpo, text=f"🔒 {aviso}", bg=tema.FUNDO,
                 fg=tema.TEXTO_SECUNDARIO if cifrado else tema.REVISAR,
                 font=("Segoe UI", 9), wraplength=520, justify="left").pack(anchor="w", pady=(6, 14))

        grade = tk.Frame(corpo, bg=tema.FUNDO)
        grade.pack(fill="x")
        for linha, (nome, rotulo, url) in enumerate(cofre.CHAVES):
            tk.Label(grade, text=rotulo, bg=tema.FUNDO, fg="white",
                     font=("Segoe UI", 10, "bold")).grid(row=linha * 2, column=0, sticky="w", pady=(8, 0))

            estado = tk.Label(grade, bg=tema.FUNDO, font=("Segoe UI", 8))
            estado.grid(row=linha * 2, column=1, sticky="w", padx=(10, 0), pady=(8, 0))

            link = tk.Label(grade, text=t("cfg_get_key"), bg=tema.FUNDO, fg=tema.LINK,
                            font=("Segoe UI", 8, "underline"), cursor="hand2")
            link.grid(row=linha * 2, column=2, sticky="e", pady=(8, 0))
            link.bind("<Button-1>", lambda e, u=url: webbrowser.open(u))

            campo = ttk.Entry(grade, width=self.LARGURA_CAMPO, style="Custom.TEntry", show="•")
            campo.grid(row=linha * 2 + 1, column=0, columnspan=2, sticky="we", pady=(2, 0))
            campo.insert(0, salvas.get(nome, ""))

            botao = ttk.Button(grade, text=t("cfg_show"), style="Secondary.TButton", width=9)
            botao.grid(row=linha * 2 + 1, column=2, sticky="e", padx=(8, 0), pady=(2, 0))
            botao.config(command=lambda n=nome: self._alternar_visibilidade(n))

            self.campos[nome] = campo
            self.revelado[nome] = (botao, estado)
            campo.bind("<KeyRelease>", lambda e, n=nome: self._atualizar_estado(n))
            self._atualizar_estado(nome)
        grade.columnconfigure(1, weight=1)

        self.legado = cofre.localizar_api_env(_diretorio_base())
        if self.legado:
            quadro = tk.Frame(corpo, bg=tema.FUNDO_CAMPO, padx=12, pady=10)
            quadro.pack(fill="x", pady=(16, 0))
            tk.Label(quadro, text=f"⚠ {t('cfg_legacy_found')}", bg=tema.FUNDO_CAMPO, fg=tema.REVISAR,
                     font=("Segoe UI", 9), wraplength=500, justify="left").pack(anchor="w")
            tk.Label(quadro, text=self.legado, bg=tema.FUNDO_CAMPO, fg=tema.TEXTO_SECUNDARIO,
                     font=("Consolas", 8), wraplength=500, justify="left").pack(anchor="w", pady=(4, 6))
            ttk.Button(quadro, text=t("cfg_legacy_delete"), style="Danger.TButton",
                       command=self._remover_legado).pack(anchor="w")
            self.quadro_legado = quadro

        tk.Label(corpo, text=t("cfg_test_cost"), bg=tema.FUNDO, fg=tema.TEXTO_SECUNDARIO,
                 font=("Segoe UI", 8), justify="left").pack(anchor="w", pady=(14, 0))

        rodape = tk.Frame(corpo, bg=tema.FUNDO)
        rodape.pack(fill="x", pady=(6, 0))
        ttk.Button(rodape, text=t("cfg_erase"), style="Danger.TButton",
                   command=self._apagar_tudo).pack(side="left")
        self.botao_testar = ttk.Button(rodape, text=t("cfg_test"), style="Secondary.TButton",
                                       command=self._testar)
        self.botao_testar.pack(side="left", padx=(8, 0))
        ttk.Button(rodape, text=t("cfg_save"), style="Primary.TButton",
                   command=self._salvar).pack(side="right")
        ttk.Button(rodape, text=t("cfg_cancel"), style="Secondary.TButton",
                   command=self.destroy).pack(side="right", padx=(0, 8))

        self.bind("<Escape>", lambda e: self.destroy())
        self.bind("<Return>", lambda e: self._salvar())
        self._centralizar(master)
        self.grab_set()
        self.focus_force()
        primeiro = next(iter(self.campos.values()), None)
        if primeiro:
            primeiro.focus_set()

    def _centralizar(self, master):
        self.update_idletasks()
        largura, altura = self.winfo_width(), self.winfo_height()
        try:
            x = master.winfo_rootx() + (master.winfo_width() - largura) // 2
            y = master.winfo_rooty() + (master.winfo_height() - altura) // 3
        except tk.TclError:
            x = y = 100
        self.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _atualizar_estado(self, nome):
        _, estado = self.revelado[nome]
        if self.campos[nome].get().strip():
            estado.config(text=f"● {t('cfg_configured')}", fg="#00c853")
        else:
            estado.config(text=f"○ {t('cfg_not_configured')}", fg="#777777")

    def _alternar_visibilidade(self, nome):
        campo = self.campos[nome]
        botao, _ = self.revelado[nome]
        if campo.cget("show"):
            campo.config(show="")
            botao.config(text=t("cfg_hide"))
        else:
            campo.config(show="•")
            botao.config(text=t("cfg_show"))

    # ---------- teste de conexao ----------

    ESTADO_TESTE = {
        api.FONTE_OK: ("✓", "cfg_test_ok", tema.LIMPO),
        api.FONTE_SEM_CHAVE: ("✗", "cfg_test_rejected", tema.MALICIOSO),
        api.FONTE_COTA: ("▲", "source_quota", tema.REVISAR),
        api.FONTE_INDISPONIVEL: ("✗", "source_unavailable", tema.MALICIOSO),
    }

    def _testar(self):
        chaves = {nome: campo.get().strip() for nome, campo in self.campos.items()}
        if not any(chaves.values()):
            messagebox.showinfo(t("cfg_test"), t("cfg_test_none"), parent=self)
            return
        self.botao_testar.config(state="disabled")
        for nome, valor in chaves.items():
            if valor:
                self.revelado[nome][1].config(text=f"◌ {t('cfg_testing')}",
                                              fg=tema.TEXTO_SECUNDARIO)
        Thread(target=self._testar_em_segundo_plano, args=(chaves,), daemon=True).start()

    def _testar_em_segundo_plano(self, chaves):
        """A consulta e de rede: nao pode rodar na thread do Tk, e o retorno volta por after."""
        try:
            resultados = api.testar_fontes(chaves)
        except Exception:
            _log.exception("falha inesperada ao testar as chaves")
            resultados = {}
        self._agendar(lambda: self._mostrar_resultado_teste(chaves, resultados))

    def _agendar(self, acao):
        try:
            self.after(0, acao)
        except tk.TclError:
            pass   # janela fechada antes do teste voltar

    def _mostrar_resultado_teste(self, chaves, resultados):
        for nome in self.campos:
            if not chaves.get(nome):
                continue
            estado = resultados.get(nome, api.FONTE_INDISPONIVEL)
            simbolo, chave_texto, cor = self.ESTADO_TESTE[estado]
            self.revelado[nome][1].config(text=f"{simbolo} {t(chave_texto)}", fg=cor)
        try:
            self.botao_testar.config(state="normal")
        except tk.TclError:
            pass

    def _salvar(self):
        valores = {nome: campo.get().strip() for nome, campo in self.campos.items()}
        try:
            caminho = salvar_chaves(valores)
        except Exception as e:
            _log.exception("falha ao gravar as chaves no cofre")
            messagebox.showerror(t("error"), f"{t('cfg_save_error')}: {e}", parent=self)
            return
        messagebox.showinfo(t("cfg_saved_title"), t("cfg_saved").format(caminho=caminho), parent=self)
        self.destroy()

    def _apagar_tudo(self):
        if not messagebox.askyesno(t("cfg_erase"), t("cfg_erase_confirm"), parent=self):
            return
        cofre.apagar()
        reload_api_keys(forcar=True)
        for nome, campo in self.campos.items():
            campo.delete(0, tk.END)
            self._atualizar_estado(nome)
        messagebox.showinfo(t("done"), t("cfg_erased"), parent=self)

    def _remover_legado(self):
        if not messagebox.askyesno(t("cfg_legacy_delete"),
                                   t("cfg_legacy_confirm").format(caminho=self.legado),
                                   parent=self):
            return
        try:
            os.remove(self.legado)
        except OSError as e:
            messagebox.showerror(t("error"), f"{t('cfg_legacy_delete_error')}: {e}", parent=self)
            return
        self.quadro_legado.destroy()
        self.legado = None
        messagebox.showinfo(t("done"), t("cfg_legacy_deleted"), parent=self)
