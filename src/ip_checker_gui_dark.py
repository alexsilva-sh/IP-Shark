import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinter import ttk
import pyperclip
import threading
import time
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from queue import Queue, Empty
from ip_checker_core import check_hash_ibm
from ip_checker_core import check_hash_alienvault
from ip_checker_core import check_hash_joesandbox
from ip_checker_core import check_url_alienvault
from ip_checker_core import check_url_virustotal, check_url_ibm
from concurrent.futures import as_completed
import ipaddress
import base64
import re
import requests
from urllib.parse import urlparse
import socket
import subprocess
import os
import sys
import webbrowser
import secure_store
import ip_checker_core as core

__version__ = "v3.1"

import importlib.util

def _load_locale(name):
    if getattr(sys, 'frozen', False):
        locale_path = os.path.join(sys._MEIPASS, "locales", f"{name}.py")
    else:
        locale_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "locales", f"{name}.py")
    spec = importlib.util.spec_from_file_location(name, locale_path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod.STRINGS

PT = _load_locale("pt_BR")
EN = _load_locale("en_US")

LANGUAGES = {
    "pt": PT,
    "en": EN
}

CURRENT_LANG = "pt"

def t(key: str) -> str:
    return LANGUAGES[CURRENT_LANG].get(key, key)

def _t_plural(key: str, itens) -> str:
    """Escolhe a variante _one ou _many conforme a quantidade e preenche {lista}."""
    texto = t(f"{key}_one" if len(itens) == 1 else f"{key}_many")
    if "{lista}" in texto:
        texto = texto.format(lista=", ".join(sorted(itens)))
    return texto

def format_ip_output_gui(data, index=None, total=1):
    status_map = {
        "clean": t("reputation_clean"),
        "bad": t("reputation_bad"),
        "whitelisted": f"{t('reputation_clean')} ({t('whitelisted')})",
        "whitelisted_bad": t("reputation_whitelisted_bad"),
        "incompleto": t("verdict_incomplete"),
    }
    if total == 1:
        header = f"[{data['ip']}] - {status_map[data['status']]}"
    else:
        header = f"[{index}] {data['ip']} - {status_map[data['status']]}"
    estados = data.get("estados", {})
    lines = [header]
    if data.get("fontes_indisponiveis"):
        lines.append(t("sources_incomplete").format(fontes=", ".join(data["fontes_indisponiveis"])))
    lines.append(f"{t('abuseipdb_score')}: "
                 f"{texto_fonte(data['abuse_score'], estados.get('abuse'), '%')}")
    lines.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if data["ibm_score"] or estados.get("ibm") in core.ESTADOS_SEM_RESPOSTA:
        lines.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    lines.append(f"{t('domain_label')}: {data['domain']}")
    lines.append(f"{t('country_city_label')}: {data['country']}, {data['city']}")
    if data["last_report"]:
        lines.append(f"{t('last_report_label')}: {data['last_report']}")
    else:
        lines.append(f"{t('last_report_label')}: {t('no_records')}")
    lines.append(f"- {data['links']['abuse']}")
    lines.append(f"- {data['links']['vt']}")
    if data['links'].get("ibm"):
        lines.append(f"- {data['links']['ibm']}")
    return "\n".join(lines)

def linha_csv_ip(data, com_ibm):
    estados = data.get("estados", {})
    linha = [data["ip"],
             texto_fonte(data["abuse_score"], estados.get("abuse"), "%"),
             texto_fonte(data["vt_score"], estados.get("vt"))]
    if com_ibm:
        linha.append(texto_fonte(data["ibm_score"] or "", estados.get("ibm")))
    linha += [data["domain"], data["country"], data["city"],
              data["last_report"] or t("no_reports"),
              data["links"]["abuse"], data["links"]["vt"]]
    if com_ibm:
        linha.append(data["links"]["ibm"] or "")
    return linha


def colunas_ip(data, ultima):
    estados = data.get("estados", {})
    return (data["ip"], t(VERDICT_KEYS[data["status"]]),
            coluna_fonte(data["abuse_score"], estados.get("abuse"), "%"),
            coluna_fonte(data["vt_score"], estados.get("vt")),
            coluna_fonte(data["ibm_score"] or "-", estados.get("ibm")),
            ultima)


def set_language(lang):
    global CURRENT_LANG, app
    CURRENT_LANG = lang
    os.environ["APP_LANG"] = lang
    if app:
        app.refresh_language()
    update_language_buttons()

def check_latest_version():
    try:
        repo = "alexsilva-sh/IP-Shark"
        url = f"https://api.github.com/repos/{repo}/releases/latest"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            latest = data["tag_name"]
            body = data.get("body", "")
            if latest != __version__:
                return latest, body
    except Exception:
        pass
    return None, None

def _diretorio_base():
    if getattr(sys, 'frozen', False):
        return os.path.dirname(sys.executable)
    return os.path.dirname(os.path.abspath(__file__))


class ConfigAPIDialog(tk.Toplevel):
    """Janela de configuracao das chaves de API."""
    LARGURA_CAMPO = 46

    def __init__(self, master):
        super().__init__(master)
        self.title(t("cfg_title"))
        self.configure(bg="#1e1e1e")
        self.resizable(False, False)
        self.transient(master)

        salvas = carregar_chaves_salvas()
        self.campos = {}
        self.revelado = {}

        corpo = tk.Frame(self, bg="#1e1e1e", padx=22, pady=18)
        corpo.pack(fill="both", expand=True)

        ttk.Label(corpo, text=t("cfg_title"), style="Title.TLabel").pack(anchor="w")

        aviso = t("cfg_intro") if secure_store.criptografia_disponivel() else t("cfg_intro_sem_cripto")
        cor_aviso = "#9aa0a6" if secure_store.criptografia_disponivel() else "#ffb020"
        tk.Label(corpo, text=f"🔒 {aviso}", bg="#1e1e1e", fg=cor_aviso,
                 font=("Segoe UI", 9), wraplength=520, justify="left").pack(anchor="w", pady=(6, 14))

        grade = tk.Frame(corpo, bg="#1e1e1e")
        grade.pack(fill="x")
        for linha, (nome, rotulo, url) in enumerate(secure_store.CHAVES):
            tk.Label(grade, text=rotulo, bg="#1e1e1e", fg="white",
                     font=("Segoe UI", 10, "bold")).grid(row=linha * 2, column=0, sticky="w", pady=(8, 0))

            estado = tk.Label(grade, bg="#1e1e1e", font=("Segoe UI", 8))
            estado.grid(row=linha * 2, column=1, sticky="w", padx=(10, 0), pady=(8, 0))

            link = tk.Label(grade, text=t("cfg_get_key"), bg="#1e1e1e", fg="#4da3ff",
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

        self.legado = secure_store.localizar_api_env(_diretorio_base())
        if self.legado:
            quadro = tk.Frame(corpo, bg="#2a2a2a", padx=12, pady=10)
            quadro.pack(fill="x", pady=(16, 0))
            tk.Label(quadro, text=f"⚠ {t('cfg_legacy_found')}", bg="#2a2a2a", fg="#ffb020",
                     font=("Segoe UI", 9), wraplength=500, justify="left").pack(anchor="w")
            tk.Label(quadro, text=self.legado, bg="#2a2a2a", fg="#9aa0a6",
                     font=("Consolas", 8), wraplength=500, justify="left").pack(anchor="w", pady=(4, 6))
            ttk.Button(quadro, text=t("cfg_legacy_delete"), style="Danger.TButton",
                       command=self._remover_legado).pack(anchor="w")
            self.quadro_legado = quadro

        rodape = tk.Frame(corpo, bg="#1e1e1e")
        rodape.pack(fill="x", pady=(18, 0))
        ttk.Button(rodape, text=t("cfg_erase"), style="Danger.TButton",
                   command=self._apagar_tudo).pack(side="left")
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

    def _salvar(self):
        valores = {nome: campo.get().strip() for nome, campo in self.campos.items()}
        try:
            caminho = salvar_chaves(valores)
        except Exception as e:
            messagebox.showerror(t("error"), f"{t('cfg_save_error')}: {e}", parent=self)
            return
        messagebox.showinfo(t("cfg_saved_title"), t("cfg_saved").format(caminho=caminho), parent=self)
        self.destroy()

    def _apagar_tudo(self):
        if not messagebox.askyesno(t("cfg_erase"), t("cfg_erase_confirm"), parent=self):
            return
        secure_store.apagar()
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


def abrir_config_api():
    janela = app.root if app else None
    ConfigAPIDialog(janela)

from ip_checker_core import (
    is_valid_ip,
    check_ip_abuseipdb,
    check_ip_virustotal,
    check_ip_ibm,
    start_browser,
    get_location,
    get_domain_from_abuseipdb,
    save_to_csv,
    check_hash_virustotal,
    safe_get,
    build_ip_result,
    carregar_chaves_salvas,
    salvar_chaves,
    reload_api_keys
)

def is_valid_hash(h):
    h = h.lower()
    return (
        re.fullmatch(r"[a-f0-9]{32}", h) or  #MD5
        re.fullmatch(r"[a-f0-9]{40}", h) or  #SHA1
        re.fullmatch(r"[a-f0-9]{64}", h)     #SHA256
    )

class ToggleSwitch(tk.Frame):
    def __init__(self, master, text="", variable=None, on_bg="#00c853", off_bg="#3a3a3a", width=48, height=26, state="normal", **kw):
        super().__init__(master, bg=master["bg"], **kw)
        self.var=variable or tk.BooleanVar(value=False); self.state=state; self.on_bg=on_bg; self.off_bg=off_bg
        self.canvas=tk.Canvas(self,width=width,height=height,highlightthickness=0,bg=master["bg"]); self.canvas.pack(side="left")
        self.label=tk.Label(self,text=text,fg="white",bg=master["bg"]); self.label.pack(side="left",padx=(6,0))
        r=height//2-2; self.x=2
        self.l=self.canvas.create_oval(2,2,height-2,height-2,fill=off_bg,outline="")
        self.m=self.canvas.create_rectangle(height//2,2,width-height//2,height-2,fill=off_bg,outline="")
        self.r=self.canvas.create_oval(width-height+2,2,width-2,height-2,fill=off_bg,outline="")
        self.shadow=self.canvas.create_oval(3,3,3+2*r,3+2*r,fill="#000",outline="",stipple="gray25")
        self.knob=self.canvas.create_oval(2,2,2+2*r,2+2*r,fill="#fff",outline="")
        self.canvas.bind("<Button-1>",self._toggle); self.label.bind("<Button-1>",self._toggle)
        self.canvas.bind("<Enter>",lambda e:self._hover(True)); self.canvas.bind("<Leave>",lambda e:self._hover(False))
        self._update()
        if state=="disabled": self._disable()
    def _set_track(self,c):
        for p in (self.l,self.m,self.r): self.canvas.itemconfig(p,fill=c)
    def _toggle(self,_=None):
        if self.state=="disabled": return
        self.var.set(not self.var.get()); self._update()
    def _update(self):
        w=int(self.canvas["width"]); h=int(self.canvas["height"]); r=h//2-2
        target=w-2-2*r if self.var.get() else 2; self._set_track(self.on_bg if self.var.get() else self.off_bg)
        for i in range(8):
            nx=self.x+(target-self.x)*(i+1)/8
            self.canvas.after(i*10,lambda x=nx:self._move(x))
        self.x=target
    def _move(self,x):
        h=int(self.canvas["height"]); r=h//2-2
        self.canvas.coords(self.knob,x,2,x+2*r,2+2*r); self.canvas.coords(self.shadow,x+1,3,x+1+2*r,3+2*r)
    def _hover(self,on):
        if self.state!="disabled" and self.var.get(): self._set_track("#2ee96b" if on else self.on_bg)
    def _disable(self):
        self.label.config(fg="#666"); self._set_track("#2a2a2a"); self.canvas.itemconfig(self.knob,fill="#888"); self.canvas.itemconfig(self.shadow,fill="")
    def set_state(self,s):
        self.state=s; self._disable() if s=="disabled" else self._update()
    def set_text(self,t):
        self.label.config(text=t)


VERDICT_KEYS = {
    "clean": "verdict_clean",
    "whitelisted": "verdict_whitelisted",
    "whitelisted_bad": "verdict_review",
    "bad": "verdict_bad",
    "incompleto": "verdict_incomplete",
    "unknown": "verdict_unknown",
}

VERDICT_TAGS = {
    "clean": "clean",
    "whitelisted": "clean",
    "whitelisted_bad": "review",
    "bad": "bad",
    "incompleto": "review",
    "unknown": "unknown",
}

ESTADO_TEXTO = {
    core.FONTE_SEM_CHAVE: "source_no_key",
    core.FONTE_COTA: "source_quota",
    core.FONTE_INDISPONIVEL: "source_unavailable",
    core.FONTE_SEM_DADOS: "source_no_data",
}


def texto_fonte(valor, estado, sufixo=""):
    """Score da fonte quando ela respondeu; o motivo da ausencia quando nao."""
    if estado in ESTADO_TEXTO:
        return t(ESTADO_TEXTO[estado])
    return f"{valor}{sufixo}"


def coluna_fonte(valor, estado, sufixo=""):
    """Versao curta para a celula da tabela; o motivo completo fica no detalhe."""
    if estado in core.ESTADOS_SEM_RESPOSTA:
        return "!"
    if estado == core.FONTE_SEM_DADOS:
        return "-"
    return f"{valor}{sufixo}"


def dividir_entrada(bruto):
    return [p for p in re.split(r"[\s,;]+", bruto or "") if p]


class MultilineInput(tk.Frame):
    """Campo de varias linhas com contador ao vivo do conteudo colado."""

    def __init__(self, master, contador, altura=4):
        super().__init__(master, bg=master["bg"])
        self._contador = contador
        self.texto = tk.Text(self, height=altura, bg="#2a2a2a", fg="white", insertbackground="white",
                             font=("Consolas", 10), relief=tk.FLAT, wrap=tk.WORD, padx=8, pady=6,
                             undo=True)
        self.texto.pack(fill="x")
        self.resumo = tk.Label(self, bg=master["bg"], fg="#9aa0a6", font=("Segoe UI", 9), anchor="w")
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

        painel = tk.PanedWindow(self, orient="vertical", bg="#1e1e1e", sashwidth=6,
                                sashrelief="flat", bd=0, sashpad=0)
        painel.pack(fill="both", expand=True)

        quadro_tabela = tk.Frame(painel, bg="#1e1e1e")
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

        self.tree.tag_configure("bad", foreground="#ff4444")
        self.tree.tag_configure("review", foreground="#ffb020")
        self.tree.tag_configure("clean", foreground="#00ff99")
        self.tree.tag_configure("unknown", foreground="#9aa0a6")
        self.tree.bind("<<TreeviewSelect>>", self._ao_selecionar)

        quadro_detalhe = tk.Frame(painel, bg="#1e1e1e")
        self.detalhe = scrolledtext.ScrolledText(quadro_detalhe, wrap=tk.WORD, bg="#0f0f0f",
                                                 fg="#dddddd", font=("Consolas", 10),
                                                 relief=tk.FLAT, height=altura_detalhe,
                                                 padx=10, pady=8)
        self.detalhe.pack(fill="both", expand=True)
        self.detalhe.tag_configure("cabecalho", font=("Consolas", 10, "bold"))
        self.detalhe.tag_configure("dica", foreground="#6b6b6b")
        self.detalhe.tag_configure("preambulo", foreground="#ffb020")
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
                self.detalhe.tag_configure(tag, foreground="#4da3ff", underline=True)
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
        raizes = list(self.tree.get_children(""))
        pares = [(self._chave_ordem(self._valor(iid, coluna)), iid) for iid in raizes]
        pares.sort(reverse=invertido)
        for pos, (_chave, iid) in enumerate(pares):
            self.tree.move(iid, "", pos)
        self._ordenacao = (coluna, invertido)

    def _valor(self, iid, coluna):
        return self.tree.item(iid, "text") if coluna == "#0" else self.tree.set(iid, coluna)

    @staticmethod
    def _chave_ordem(valor):
        bruto = str(valor).strip().rstrip("%")
        try:
            return (0, float(bruto), "")
        except ValueError:
            return (1, 0.0, str(valor).lower())


class DriverIndisponivel(Exception):
    def __init__(self, vivos, tamanho):
        self.vivos = vivos
        self.tamanho = tamanho
        super().__init__(f"nenhum navegador disponivel ({vivos}/{tamanho})")


class DriverPool:
    """Pool de navegadores do X-Force.

    O tamanho e calibragem medida: 3 sustenta o paralelismo sem disparar o bloqueio
    do servico. Esta classe cuida do resto -- boot, timeout e substituicao.
    """

    TENTATIVAS = 3
    ESPERA_ENTRE_TENTATIVAS = 3
    TIMEOUT_EMPRESTIMO = 120

    def __init__(self, tamanho=3, ao_degradar=None):
        self.tamanho = tamanho
        self.fila = Queue()
        self.todos = []
        self.vivos = 0
        self.ultimo_erro = ""
        self.boot_concluido = threading.Event()
        self._lock = threading.Lock()
        self._ao_degradar = ao_degradar

    def iniciar_async(self):
        Thread(target=self._boot, daemon=True).start()

    def _boot(self):
        # Em paralelo: serial triplicava o tempo ate o pool ficar utilizavel.
        with ThreadPoolExecutor(max_workers=self.tamanho) as executor:
            list(executor.map(self._subir_um, range(self.tamanho)))
        self.boot_concluido.set()
        if self.vivos < self.tamanho and self._ao_degradar:
            self._ao_degradar(self.vivos, self.tamanho, self.ultimo_erro)

    def _subir_um(self, _indice=0):
        for tentativa in range(self.TENTATIVAS):
            try:
                driver = start_browser()
            except Exception as e:
                self.ultimo_erro = str(e)
                if tentativa < self.TENTATIVAS - 1:
                    time.sleep(self.ESPERA_ENTRE_TENTATIVAS)
                continue
            with self._lock:
                self.todos.append(driver)
                self.vivos += 1
            self.fila.put(driver)
            return True
        return False

    @contextmanager
    def emprestar(self):
        """Empresta um driver; levanta DriverIndisponivel em vez de pendurar para sempre."""
        if self.boot_concluido.is_set() and self.vivos == 0:
            raise DriverIndisponivel(0, self.tamanho)
        try:
            driver = self.fila.get(timeout=self.TIMEOUT_EMPRESTIMO)
        except Empty:
            raise DriverIndisponivel(self.vivos, self.tamanho)
        try:
            yield driver
        finally:
            if self._vivo(driver):
                self.fila.put(driver)
            else:
                self._descartar(driver)

    @staticmethod
    def _vivo(driver):
        try:
            driver.window_handles
            return True
        except Exception:
            return False

    def _descartar(self, driver):
        """Navegador morto nao volta para a fila: envenenaria toda consulta seguinte."""
        with self._lock:
            self.vivos -= 1
            if driver in self.todos:
                self.todos.remove(driver)
            repor = self.vivos < self.tamanho
        try:
            driver.quit()
        except Exception:
            pass
        if repor:
            Thread(target=self._subir_um, daemon=True).start()

    def encerrar(self):
        with self._lock:
            drivers = set(self.todos)
            self.todos.clear()
            self.vivos = 0
        while True:
            try:
                drivers.add(self.fila.get_nowait())
            except Empty:
                break
        if not drivers:
            return
        def _quit(d):
            try:
                d.quit()
            except Exception:
                pass
        with ThreadPoolExecutor(max_workers=len(drivers)) as executor:
            list(executor.map(_quit, drivers))


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
        quadro = tk.Frame(pagina, bg="#1e1e1e")
        quadro.pack(fill="x", padx=10, pady=(2, 6))
        barra = ttk.Progressbar(quadro, style="Scan.Horizontal.TProgressbar",
                                mode="determinate", maximum=1, value=0)
        barra.pack(fill="x")
        rotulo = ttk.Label(quadro, text="", style="Status.TLabel")
        rotulo.pack(anchor="w", pady=(3, 0))
        return barra, rotulo

    @staticmethod
    def _contar_ips(bruto):
        validos = invalidos = privados = 0
        for item in dividir_entrada(bruto):
            if not is_valid_ip(item):
                invalidos += 1
            elif ipaddress.ip_address(item).is_private:
                privados += 1
            else:
                validos += 1
        if not (validos or invalidos or privados):
            return ""
        partes = [f"{validos} {t('count_valid')}"]
        if invalidos:
            partes.append(f"{invalidos} {t('count_invalid')}")
        if privados:
            partes.append(f"{privados} {t('count_private')}")
        return " · ".join(partes)

    @staticmethod
    def _contar_hashes(bruto):
        itens = dividir_entrada(bruto)
        if not itens:
            return ""
        validos = sum(1 for h in itens if re.fullmatch(r"[a-fA-F0-9]{32,64}", h))
        partes = [f"{validos} {t('count_valid')}"]
        if len(itens) - validos:
            partes.append(f"{len(itens) - validos} {t('count_invalid')}")
        return " · ".join(partes)

    @staticmethod
    def _contar_dominios(bruto):
        itens = dividir_entrada(bruto)
        return f"{len(itens)} {t('count_items')}" if itens else ""

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

    FONTES_NOMES = {"abuse": "AbuseIPDB", "vt": "VirusTotal",
                    "ibm": "IBM X-Force", "alien": "AlienVault"}

    @classmethod
    def _registrar_cota(cls, destino, estados):
        for chave, estado in (estados or {}).items():
            if estado == core.FONTE_COTA:
                destino.add(cls.FONTES_NOMES.get(chave, chave))

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
        root.title(f"IP Shark {__version__} - by @alexsilva.sh in Github")
        self.root.configure(bg="#1e1e1e")        
        self.currently_processing = set()
        self.root = root
        root.title(f"IP Shark {__version__} - by @alexsilva.sh in Github")
        self.root.configure(bg="#1e1e1e")
        self.tab_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.tab_frame.pack(pady=(5, 0))
        self.banner = tk.Frame(self.root, bg="#3a2a12")
        self.banner_label = tk.Label(self.banner, bg="#3a2a12", fg="#ffb020",
                                     font=("Segoe UI", 9), justify="left", wraplength=1000)
        self.banner_label.pack(side="left", padx=12, pady=6)
        self.ip_button = ttk.Button(self.tab_frame,text=t("tab_ip"),command=self.show_ip_page,style="NavActive.TButton")
        self.ip_button.grid(row=0,column=0,padx=5)        
        self._register_i18n(self.ip_button, "tab_ip")
        self.hash_button = ttk.Button(self.tab_frame,text=t("tab_hash"),command=self.show_hash_page,style="Nav.TButton")
        self.hash_button.grid(row=0, column=1, padx=5)
        self.page_ip = tk.Frame(root, bg="#1e1e1e")
        self.page_ip.pack(fill=tk.BOTH, expand=True)
        self.page_hash = tk.Frame(root, bg="#1e1e1e")
        self.page_hash.pack_forget()
        self.driver_pool = DriverPool(ao_degradar=self._avisar_pool_degradado)
        self._init_drivers_async()

        # CONTEUDO DA ABA IP
        self.input_label = ttk.Label(self.page_ip,text=t("paste_ips"),style="Title.TLabel")
        self.input_label.pack(pady=(10,2))
        self._register_i18n(self.input_label, "paste_ips")
        self.entry = MultilineInput(self.page_ip, self._contar_ips)
        self.entry.pack(pady=6, padx=20, fill="x")

        # ---------- interruptores (aba IP) ---------------------------
        toggles_ip = tk.Frame(self.page_ip, bg="#1e1e1e")
        toggles_ip.pack(pady=6)
        self.ibm_var_ip = tk.BooleanVar(value=True)
        self.toggle_ibm_ip = ToggleSwitch(toggles_ip, text=t("toggle_ibm"), variable=self.ibm_var_ip)
        self.toggle_ibm_ip.pack(side="left", padx=(0,15))
        self._register_i18n(self.toggle_ibm_ip.label, "toggle_ibm")
        col_ip = tk.Frame(toggles_ip, bg="#1e1e1e")
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
        self.button_frame = tk.Frame(self.page_ip, bg="#1e1e1e")
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
        self.hash_entry = MultilineInput(self.page_hash, self._contar_hashes)
        self.hash_entry.pack(pady=6, padx=20, fill="x")

        # ---------- interruptores (aba HASH) ---------------------------
        toggles_hash = tk.Frame(self.page_hash, bg="#1e1e1e")
        toggles_hash.pack(pady=6)

        self.ibm_var_hash = tk.BooleanVar(value=True)
        self.toggle_ibm_hash = ToggleSwitch(toggles_hash, text=t("toggle_ibm"), variable=self.ibm_var_hash)
        self.toggle_ibm_hash.pack(side="left", padx=(0,15))
        self._register_i18n(self.toggle_ibm_hash.label, "toggle_ibm")

        col_hash = tk.Frame(toggles_hash, bg="#1e1e1e")
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

        self.hash_button_frame = tk.Frame(self.page_hash, bg="#1e1e1e")
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
        self.page_url = tk.Frame(root, bg="#1e1e1e")
        self.page_url.pack_forget()
        self.input_label_url = ttk.Label(self.page_url,text=t("paste_domains"),style="Title.TLabel")
        self._register_i18n(self.url_button, "tab_domain")
        self._register_i18n(self.input_label_url, "paste_domains")
        self.input_label_url.pack(pady=(10, 2))
        self.url_entry = MultilineInput(self.page_url, self._contar_dominios)
        self.url_entry.pack(pady=6, padx=20, fill="x")
        toggles_url = tk.Frame(self.page_url, bg="#1e1e1e")
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
        col_url = tk.Frame(toggles_url, bg="#1e1e1e")
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
        self.url_button_frame = tk.Frame(self.page_url, bg="#1e1e1e")
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
                    self._registrar_cota(self.cota_hash, estados)
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
                blocos.append(_t_plural(chave, self.bad_hashes))
            elif not self.incompletos_hash:
                blocos.append(_t_plural("hash_clean", self.results_hash))
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
                            estado_ibm = core.classificar_ibm(ibm_score)
                            if estado_ibm == core.FONTE_SEM_DADOS:
                                ibm_score = t("unknown")
                        except DriverIndisponivel:
                            ibm_score, estado_ibm = None, core.FONTE_INDISPONIVEL
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
                    self._registrar_cota(self.cota_url, estados)
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
                            self._registrar_cota(self.cota_url, ip_estados)
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
            blocos.append(_t_plural(chave, self.bad_urls))
        if self.review_urls:
            blocos.append(_t_plural("ip_whitelist_review", self.review_urls))
        if not self.bad_urls and not self.review_urls and not self.incompletos_url:
            blocos.append(_t_plural("url_clean", self.results_url))
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
        if estado_vt == core.FONTE_OK and (vt_score or 0) > 0:
            is_malicious = True
        if estado_ibm == core.FONTE_OK:
            try:
                if float(ibm_score) >= 2:
                    is_malicious = True
            except (ValueError, TypeError):
                if str(ibm_score).strip().lower() in ("high", "medium"):
                    is_malicious = True
        if estado_alien == core.FONTE_OK and str(alien_score).strip() not in ("0", "-", ""):
            is_malicious = True

        fontes_fora = [nome for nome, estado in (
            ("VirusTotal", estado_vt), ("IBM X-Force", estado_ibm), ("AlienVault", estado_alien)
        ) if estado in core.ESTADOS_SEM_RESPOSTA]
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
                estado_ibm = core.classificar_ibm(ibm_score)
                if estado_ibm == core.FONTE_SEM_DADOS:
                    ibm_score = t("unknown")
            except DriverIndisponivel:
                ibm_score, estado_ibm = None, core.FONTE_INDISPONIVEL

            if isinstance(ibm_score, str) and ibm_score.strip().lower() in ("high", "medium"):
                malicioso = True
                reputation = t("reputation_bad")

        # AlienVault
        alien_score, alien_link, estado_alien = check_hash_alienvault(h)
        if estado_alien == core.FONTE_OK and alien_score not in ("0", None):
            malicioso = True

        # VirusTotal
        result, estado_vt = check_hash_virustotal(h)
        if estado_vt != core.FONTE_OK or not result or "data" not in result or "attributes" not in result["data"]:
            vt_score = None
            name = "-"
            data_fmt = "N/A"
            if estado_vt == core.FONTE_OK:
                estado_vt = core.FONTE_SEM_DADOS
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
        ) if estado in core.ESTADOS_SEM_RESPOSTA]
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

        save_to_csv(self.results_ip, headers, filename="ip_results.xlsx",
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

        save_to_csv(self.results_hash, headers, filename="hash_results.xlsx",
                    parent=self.root, titulo=t("select_folder"))

    def save_url_results(self):
        if not self.results_url:
            messagebox.showwarning(t("done"), t("no_results"))
            return
        from ip_checker_core import save_to_excel
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
        save_to_excel(
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
            ibm_score, estado_ibm = None, core.FONTE_OK
            if self.ibm_ip_ativo and not self.stop_flag:
                try:
                    with self.driver_pool.emprestar() as driver:
                        _, ibm_score = check_ip_ibm(driver, ip)
                    estado_ibm = core.classificar_ibm(ibm_score)
                    if estado_ibm == core.FONTE_SEM_DADOS:
                        ibm_score = t("unknown")
                except DriverIndisponivel:
                    ibm_score, estado_ibm = None, core.FONTE_INDISPONIVEL
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
            terminal_output = format_ip_output_gui(data, index=index, total=len(ips))
            csv_data = linha_csv_ip(data, self.ibm_ip_ativo)
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
            self._registrar_cota(self.cota_ip, data.get("estados", {}))
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
            blocos.append(_t_plural(chave, self.bad_ips))
        if self.review_ips:
            blocos.append(_t_plural("ip_whitelist_review", self.review_ips))
        # "Nada malicioso encontrado" so vale se todas as fontes responderam.
        if not self.bad_ips and not self.review_ips and not self.incompletos_ip:
            blocos.append(_t_plural("ip_clean", self.results_ip))
        self.tabela_ip.set_preamble("\n\n".join(blocos))

    def process_url_ip_associated(self, ip, domain):
        try:
            abuseipdb_result, estado_abuse = check_ip_abuseipdb(ip)
            virustotal_result, estado_vt = check_ip_virustotal(ip)
            city, country = get_location(ip)
            assoc_domain = get_domain_from_abuseipdb(abuseipdb_result)
            ibm_score, estado_ibm = None, core.FONTE_OK
            if self.ibm_url_ativo:
                try:
                    with self.driver_pool.emprestar() as driver:
                        _, ibm_score = check_ip_ibm(driver, ip)
                    estado_ibm = core.classificar_ibm(ibm_score)
                    if estado_ibm == core.FONTE_SEM_DADOS:
                        ibm_score = t("unknown")
                except DriverIndisponivel:
                    ibm_score, estado_ibm = None, core.FONTE_INDISPONIVEL
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
            return (format_ip_output_gui(data), data["status"],
                    linha_csv_ip(data, self.ibm_url_ativo), colunas_ip(data, "-"),
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

import webbrowser
from tkinter import Toplevel, Label, Button

def _limpar_markdown(texto):
    """Converte as notas de release do GitHub em linhas legiveis fora do navegador.

    Devolve uma lista de (linha, estilo), com estilo em {"titulo", "item", "texto"}.
    """
    linhas = []
    dentro_de_codigo = False
    for bruta in (texto or "").splitlines():
        linha = bruta.rstrip()
        if linha.strip().startswith("```"):
            dentro_de_codigo = not dentro_de_codigo
            continue
        if dentro_de_codigo:
            if linha.strip():
                linhas.append((linha.strip(), "texto"))
            continue

        linha = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", linha)   # [texto](url) -> texto
        linha = linha.replace("**", "").replace("`", "")
        linha = re.sub(r"^\s*>\s?", "", linha)

        cabecalho = re.match(r"^\s*#{1,6}\s*(.+)$", linha)
        if cabecalho:
            linhas.append((cabecalho.group(1).strip(), "titulo"))
            continue

        item = re.match(r"^\s*[-*+]\s+(.+)$", linha)
        if item:
            linhas.append((item.group(1).strip(), "item"))
            continue

        if linha.strip():
            # Junta linhas seguidas num paragrafo so, deixando a quebra a cargo do widget.
            if linhas and linhas[-1][1] == "texto" and linhas[-1][0]:
                linhas[-1] = (f"{linhas[-1][0]} {linha.strip()}", "texto")
            else:
                linhas.append((linha.strip(), "texto"))
        elif linhas and linhas[-1][0]:
            linhas.append(("", "texto"))
    while linhas and not linhas[-1][0]:
        linhas.pop()
    return linhas


def show_update_window(latest_version, novidades_texto):
    update_win = Toplevel()
    update_win.title(t("update_available"))
    update_win.configure(bg="#1e1e1e")
    update_win.minsize(520, 360)

    Label(update_win, text=t("new_version_available").format(version=latest_version),
          bg="#1e1e1e", fg="white", font=("Segoe UI", 11, "bold")).pack(pady=(14, 2), padx=16, anchor="w")
    Label(update_win, text=t("whats_new"), bg="#1e1e1e", fg="#9aa0a6", anchor="w",
          font=("Segoe UI", 9)).pack(pady=(0, 8), padx=16, anchor="w")

    caixa = scrolledtext.ScrolledText(update_win, wrap=tk.WORD, bg="#141414", fg="#dddddd",
                                      font=("Segoe UI", 10), relief=tk.FLAT, height=13,
                                      width=62, padx=12, pady=10, borderwidth=0)
    caixa.pack(fill=tk.BOTH, expand=True, padx=16)
    caixa.tag_configure("titulo", foreground="#4da3ff", font=("Segoe UI", 10, "bold"),
                        spacing1=10, spacing3=4)
    caixa.tag_configure("item", lmargin1=14, lmargin2=28, spacing3=3)
    caixa.tag_configure("texto", spacing3=3)

    conteudo = _limpar_markdown(novidades_texto)
    if not conteudo:
        conteudo = [(t("cannot_load_release_notes"), "texto")]
    for linha, estilo in conteudo:
        prefixo = "• " if estilo == "item" else ""
        caixa.insert(tk.END, f"{prefixo}{linha}\n", estilo)
    caixa.config(state=tk.DISABLED)

    rodape = tk.Frame(update_win, bg="#1e1e1e")
    rodape.pack(fill="x", padx=16, pady=12)
    ttk.Button(rodape, text=t("close"), style="Secondary.TButton",
               command=update_win.destroy).pack(side="right")
    ttk.Button(rodape, text=t("download_github"), style="Primary.TButton",
               command=lambda: webbrowser.open(
                   "https://github.com/alexsilva-sh/IP-Shark/releases")).pack(side="right", padx=(0, 8))
    update_win.bind("<Escape>", lambda e: update_win.destroy())

def verificar_atualizacao_em_segundo_plano(root):
    latest, novidades = check_latest_version()
    if not latest:
        return
    try:
        root.after(0, lambda: show_update_window(latest, novidades))
    except tk.TclError:
        pass   # janela fechada antes de a verificacao terminar


def configurar_estilos(style):
    style.theme_use("clam")   # trocar de tema descarta o que ja foi configurado
    style.configure("Nav.TButton",background="#333333",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.map("Nav.TButton",background=[("active","#444444")])
    style.configure("NavActive.TButton",background="#007acc",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.configure("Secondary.TButton",background="#333333",foreground="white",font=("Segoe UI",10),padding=(10,5))
    style.map("Secondary.TButton",background=[("disabled","#262626"),("active","#222222"),("pressed","#1a1a1a")],foreground=[("disabled","#6b6b6b"),("active","white")])
    style.configure("Danger.TButton",background="#aa0000",foreground="white",font=("Segoe UI",10,"bold"),padding=(10,5))
    style.map("Danger.TButton",background=[("disabled","#3a2222"),("active","#7a0000"),("pressed","#5c0000")],foreground=[("disabled","#8a6b6b"),("active","white")])
    style.configure("Primary.TButton",background="#007acc",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.map("Primary.TButton",background=[("disabled","#2b3a45"),("active","#1e90ff"),("pressed","#0060a8")],foreground=[("disabled","#7a8b96"),("active","white")])
    style.configure("Custom.TEntry",fieldbackground="#2a2a2a",foreground="white",padding=6)
    style.configure("Status.TLabel",background="#1e1e1e",foreground="#00c853",font=("Segoe UI",9))
    style.configure("Title.TLabel",background="#1e1e1e",foreground="white",font=("Segoe UI",11,"bold"))
    style.configure("Result.Treeview",background="#0f0f0f",fieldbackground="#0f0f0f",foreground="#dddddd",font=("Consolas",10),rowheight=24,borderwidth=0)
    style.map("Result.Treeview",background=[("selected","#0a3d5c")],foreground=[("selected","white")])
    style.configure("Result.Treeview.Heading",background="#2a2a2a",foreground="white",font=("Segoe UI",9,"bold"),relief="flat",padding=(6,5))
    style.map("Result.Treeview.Heading",background=[("active","#3a3a3a")])
    style.configure("Scan.Horizontal.TProgressbar",troughcolor="#2a2a2a",bordercolor="#2a2a2a",background="#007acc",lightcolor="#007acc",darkcolor="#007acc",thickness=8)


def update_language_buttons():
    if CURRENT_LANG == "pt":
        btn_lang_pt.config(style="NavActive.TButton")
        btn_lang_en.config(style="Nav.TButton")
    else:
        btn_lang_en.config(style="NavActive.TButton")
        btn_lang_pt.config(style="Nav.TButton")

if __name__ == "__main__":
    root = tk.Tk()
    style = ttk.Style()
    configurar_estilos(style)
    root.minsize(900, 600)
    root.state('zoomed')
    root.title(f"IP Shark {__version__} - by @alexsilva.sh in Github")
    
    # --- Seletor de idioma ---
    lang_frame = tk.Frame(root, bg="#1e1e1e")
    lang_frame.pack(pady=(5, 0))

    btn_lang_pt = ttk.Button(lang_frame,text="🇧🇷 PT",command=lambda: set_language("pt"),style="Nav.TButton")
    btn_lang_pt.pack(side="left", padx=5)
    btn_lang_en = ttk.Button(lang_frame,text="🇺🇸 EN",command=lambda: set_language("en"),style="Nav.TButton")
    btn_lang_en.pack(side="left", padx=5)

    btn_config = ttk.Button(lang_frame,text=t("btn_config_api"),command=abrir_config_api,style="Secondary.TButton")
    btn_config.pack(side="left", padx=(15,5))

    btn_lang_pt.config(command=lambda: set_language("pt"))
    btn_lang_en.config(command=lambda: set_language("en"))

    if getattr(sys, 'frozen', False):
        icon_path = os.path.join(sys._MEIPASS, 'assets', 'shark.ico')
    else:
        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'assets', 'shark.ico')
        icon_path = os.path.abspath(icon_path)
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    else:
        print(f"[AVISO] Ícone não encontrado em: {icon_path}")

    app = IPCheckerApp(root)
    app._register_i18n(btn_config, "btn_config_api")
    update_language_buttons()
    root.protocol("WM_DELETE_WINDOW", app.on_close)

    # Em segundo plano: a consulta ao GitHub segurava a janela por ate 5s numa rede lenta.
    Thread(target=lambda: verificar_atualizacao_em_segundo_plano(root), daemon=True).start()

    root.mainloop()