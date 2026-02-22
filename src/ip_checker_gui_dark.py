import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinter import ttk
import pyperclip
from threading import Thread
from concurrent.futures import ThreadPoolExecutor
from queue import Queue
from ip_checker_core import check_hash_ibm
from ip_checker_core import check_hash_alienvault
from ip_checker_core import check_hash_joesandbox
from ip_checker_core import check_url_alienvault
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

__version__ = "v3.0 BETA"

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

def format_ip_output_gui(data, index=None, total=1):
    status_map = {
        "clean": t("reputation_clean"),
        "bad": t("reputation_bad"),
        "whitelisted": f"{t('reputation_clean')} ({t('whitelisted')})"
    }
    if total == 1:
        header = f"[{data['ip']}] - {status_map[data['status']]}"
    else:
        header = f"[{index}] {data['ip']} - {status_map[data['status']]}"
    lines = [header]
    lines.append(f"{t('abuseipdb_score')}: {data['abuse_score']}%")
    lines.append(f"{t('vt_score')}: {data['vt_score']}")
    if data["ibm_score"]:
        lines.append(f"{t('ibm_score')}: {data['ibm_score']}")
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

def abrir_config_api():
    if getattr(sys, 'frozen', False):
        diretorio_base = os.path.dirname(sys.executable)
    else:
        diretorio_base = os.path.dirname(os.path.abspath(__file__))
    possiveis = [
        os.path.join(diretorio_base, "config", "api.env"),
        os.path.join(diretorio_base, "..", "config", "api.env"),
        os.path.abspath(os.path.join(diretorio_base, "..", "config", "api.env")),
    ]
    caminho_api = None
    for p in possiveis:
        p = os.path.abspath(p)
        if os.path.exists(p):
            caminho_api = p
            break
    if not caminho_api:
        caminho_api = os.path.join(diretorio_base, "config", "api.env")
        os.makedirs(os.path.dirname(caminho_api), exist_ok=True)
        with open(caminho_api, "w") as f:
            f.write("ABUSEIPDB_API_KEY=\nVIRUSTOTAL_API_KEY=\nIPINFO_API_KEY=\nALIENVAULT_API_KEY=\n")
    try:
        os.startfile(caminho_api)
    except Exception as e:
        messagebox.showerror(t("error"), f"{t('cannot_open_file')}: {e}")

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
    build_ip_result
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
        
class IPCheckerApp:
    def _init_drivers_async(self, count=3):
        import time
        def _start_with_retry(index, max_retries=3):
            for attempt in range(max_retries):
                try:
                    driver = start_browser()
                    self.driver_pool.put(driver)
                    self.all_drivers.append(driver)
                    print(f"[INFO] Driver {index + 1}/{count} iniciado com sucesso")
                    return
                except Exception as e:
                    print(f"[AVISO] Driver {index + 1} tentativa {attempt + 1}/{max_retries} falhou: {e}")
                    time.sleep(3)
            print(f"[ERRO] Driver {index + 1} não pôde ser iniciado após {max_retries} tentativas")
        for i in range(count):
            _start_with_retry(i)
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
    def _register_i18n(self, widget, key, attr="text"):
        self.i18n_widgets.append((widget, key, attr))
    def _insert_colored(self, output_area, text, is_bad):
        lines = text.split("\n")
        for i, line in enumerate(lines):
            if i == 0:
                tag = "header_bad" if is_bad else "header_clean"
            else:
                tag = "bad" if is_bad else "clean"
            output_area.insert(tk.END, line + "\n", tag)
    def __init__(self, root):
        self.root = root
        self.i18n_widgets = []
        self.ip_results_by_domain = {}
        self.currently_processing = set()
        root.title(f"IP Shark {__version__} - by @alexsilva.sh in Github")
        self.root.configure(bg="#1e1e1e")        
        self.currently_processing = set()
        self.root = root
        root.title(f"IP Shark {__version__} - by @alexsilva.sh in Github")
        self.root.configure(bg="#1e1e1e")
        self.tab_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.tab_frame.pack(pady=(5, 0))
        self.ip_button = ttk.Button(self.tab_frame,text=t("tab_ip"),command=self.show_ip_page,style="NavActive.TButton")
        self.ip_button.grid(row=0,column=0,padx=5)        
        self._register_i18n(self.ip_button, "tab_ip")
        self.hash_button = ttk.Button(self.tab_frame,text=t("tab_hash"),command=self.show_hash_page,style="Nav.TButton")
        self.hash_button.grid(row=0, column=1, padx=5)
        self.page_ip = tk.Frame(root, bg="#1e1e1e")
        self.page_ip.pack(fill=tk.BOTH, expand=True)
        self.page_hash = tk.Frame(root, bg="#1e1e1e")
        self.page_hash.pack_forget()
        self.driver_pool = Queue()
        self.all_drivers = []
        Thread(target=self._init_drivers_async, daemon=True).start()
        #label_font = ("Segoe UI", 10)
        #entry_font = ("Consolas", 10)
        #button_font = ("Segoe UI", 10, "bold")
        
        # CONTEUDO DA ABA IP
        self.input_label = ttk.Label(self.page_ip,text=t("paste_ips"),style="Title.TLabel")
        self.input_label.pack(pady=(10,2))
        self._register_i18n(self.input_label, "paste_ips")
        self.entry = ttk.Entry(self.page_ip,font=("Consolas",10))
        self.entry.pack(pady=6,padx=20,fill="x")
        self.entry.configure(style="Custom.TEntry")
        
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
        self.status_label = ttk.Label(self.page_ip,text="",style="Status.TLabel")
        self.status_label.pack()
        self.button_frame = tk.Frame(self.page_ip, bg="#1e1e1e")
        self.button_frame.pack(side=tk.BOTTOM, pady=10, fill=tk.X)
        self.button_frame.grid_columnconfigure(0, weight=1)
        self.button_frame.grid_columnconfigure(4, weight=1)        
        self.output_area = scrolledtext.ScrolledText(self.page_ip,wrap=tk.NONE,bg="#0f0f0f",fg="#00ff99",insertbackground="white",font=("Consolas",10),relief=tk.FLAT)
        self.output_area.pack(padx=10, pady=(0,5), fill=tk.BOTH, expand=True)
        self.output_area.tag_configure("bad", foreground="#ff4444")
        self.output_area.tag_configure("clean", foreground="#00ff99")
        self.output_area.tag_configure("header_bad", foreground="#ff4444", font=("Consolas", 10, "bold"))
        self.output_area.tag_configure("header_clean", foreground="#00ff99", font=("Consolas", 10, "bold"))
        
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
        self.hash_entry = ttk.Entry(self.page_hash,font=("Consolas",10))
        self.hash_entry.pack(pady=6,padx=20,fill="x")
        self.hash_entry.configure(style="Custom.TEntry")
        
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
        self.hash_status_label = ttk.Label(self.page_hash,text="",style="Status.TLabel")
        self.hash_status_label.pack()
        
        self.hash_button_frame = tk.Frame(self.page_hash, bg="#1e1e1e")
        self.hash_button_frame.pack(side=tk.BOTTOM, pady=10, fill=tk.X)
        self.hash_button_frame.grid_columnconfigure(0, weight=1)
        self.hash_button_frame.grid_columnconfigure(4, weight=1)
        self.hash_output_area = scrolledtext.ScrolledText(self.page_hash,wrap=tk.NONE,bg="#0f0f0f",fg="#00ff99",insertbackground="white",font=("Consolas",10),relief=tk.FLAT)
        self.hash_output_area.pack(padx=10, pady=(0, 5), fill=tk.BOTH, expand=True)
        
        self.hash_output_area.tag_configure("bad", foreground="#ff4444")
        self.hash_output_area.tag_configure("clean", foreground="#00ff99")
        self.hash_output_area.tag_configure("header_bad", foreground="#ff4444", font=("Consolas", 10, "bold"))
        self.hash_output_area.tag_configure("header_clean", foreground="#00ff99", font=("Consolas", 10, "bold"))
        
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
        self.url_entry = ttk.Entry(self.page_url,font=("Consolas",10))
        self.url_entry.pack(pady=6,padx=20,fill="x")
        self.url_entry.configure(style="Custom.TEntry")
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
        self.url_status_label = ttk.Label(self.page_url,text="",style="Status.TLabel")
        self.url_status_label.pack()
        self.url_button_frame = tk.Frame(self.page_url, bg="#1e1e1e")
        self.url_button_frame.pack(side=tk.BOTTOM, pady=10, fill=tk.X)
        self.url_output_area = scrolledtext.ScrolledText(self.page_url,wrap=tk.NONE,bg="#0f0f0f",fg="#00ff99",insertbackground="white",font=("Consolas",10),relief=tk.FLAT)
        self.url_output_area.pack(padx=10, pady=(0, 5), fill=tk.BOTH, expand=True)
        
        self.url_output_area.tag_configure("bad", foreground="#ff4444")
        self.url_output_area.tag_configure("clean", foreground="#00ff99")
        self.url_output_area.tag_configure("header_bad", foreground="#ff4444", font=("Consolas", 10, "bold"))
        self.url_output_area.tag_configure("header_clean", foreground="#00ff99", font=("Consolas", 10, "bold"))
        
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
        self.ip_button.config(style="NavActive.TButton")
        self.hash_button.config(style="Nav.TButton")
        self.url_button.config(style="Nav.TButton")

    def show_hash_page(self):
        self.page_ip.pack_forget()
        self.page_url.pack_forget()
        self.page_hash.pack(fill=tk.BOTH, expand=True)
        self.ip_button.config(style="Nav.TButton")
        self.hash_button.config(style="NavActive.TButton")
        self.url_button.config(style="Nav.TButton")

    def show_url_page(self):
        self.page_ip.pack_forget()
        self.page_hash.pack_forget()
        self.page_url.pack(fill=tk.BOTH, expand=True)
        self.ip_button.config(style="Nav.TButton")
        self.hash_button.config(style="Nav.TButton")
        self.url_button.config(style="NavActive.TButton")

    def run_hash_check(self):
        if self.scanning_hash:
            messagebox.showwarning(t("done"), t("scan_already_running_hash"))
            return
        self.bad_hashes = set()
        self.hash_output_area.delete("1.0", tk.END)
        raw_hashes = self.hash_entry.get()
        cleaned_hashes = re.sub(r"[\s\n]+", ",", raw_hashes)
        all_hashes = [h.strip().lower() for h in cleaned_hashes.split(",") if h.strip()]
        hash_list = []
        invalid_hashes = []
        for h in all_hashes:
            if re.fullmatch(r"[a-fA-F0-9]{32,64}", h):
                hash_list.append(h)
            else:
                invalid_hashes.append(h)
        if invalid_hashes:
            messagebox.showwarning(t("invalid_hashes_title"), t("invalid_hashes_msg") + "\n" + "\n".join(invalid_hashes))
        if not hash_list:
            messagebox.showerror(t("error"), t("no_valid_hash"))
            return
        self.results_hash = []
        self.results_url = []
        self.stop_flag = False
        self.currently_processing_hashes.clear()
        self.update_status_label_hash()
        self.scanning_hash = True
        self.hash_button_action.config(state="disabled")
        def thread_run():
            try:
                for i, h in enumerate(hash_list):
                    if self.stop_flag:
                        break
                    self.currently_processing_hashes.add(h)
                    self.update_status_label_hash()
                    result_text, bad = self.process_hash(h, i + 1, total_hashes=len(hash_list))
                    if self.stop_flag:
                        break
                    if bad:
                        self.bad_hashes.add(h)
                    self._insert_colored(self.hash_output_area, result_text, bad)
                    self.hash_output_area.insert(tk.END, "\n")
                    self.hash_output_area.see(tk.END)
                    self.currently_processing_hashes.discard(h)
                    self.update_status_label_hash()
                if not self.stop_flag:
                    self._append_analysis_hash()
                    messagebox.showinfo(t("done"), t("hash_scan_finished"))
            finally:
                self.scanning_hash = False
                self.root.after(0, lambda: self.hash_button_action.config(state="normal"))
        Thread(target=thread_run, daemon=True).start()

    def _append_analysis_hash(self):
        if not self.pre_var_hash.get():
            return
        if self.bad_hashes:
            if self.mss_var_hash.get():
                texto = t("hash_bad_mss")
            else:
                texto = t("hash_bad_no_mss")
        else:
            texto = t("hash_clean")
        self.hash_output_area.insert("1.0", texto + "\n\n")
        self.hash_output_area.see("1.0")

    def run_url_check(self):
        if self.scanning_url:
            messagebox.showwarning(t("done"), t("scan_already_running_domain"))
            return
        self.results_url.clear()
        self.bad_urls = set()
        self.ip_results_by_domain = {}
        from ip_checker_core import check_url_virustotal, check_url_ibm
        self.url_output_area.delete("1.0", tk.END)
        raw_urls = self.url_entry.get()
        cleaned_urls = re.sub(r"[\s\n]+", ",", raw_urls)
        url_list = [u.strip() for u in cleaned_urls.split(",") if u.strip()]
        if not url_list:
            messagebox.showerror(t("error"), t("no_domain"))
            return
        self.stop_flag = False
        self.currently_processing_urls.clear()
        self.update_status_label_url()
        self.scanning_url = True
        self.url_button_action.config(state="disabled")
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
                    self.currently_processing_urls.add(url)
                    self.update_status_label_url()
                    if self.stop_flag:
                        break
                    result_vt = check_url_virustotal(url)
                    if self.stop_flag:
                        break
                    if result_vt.get("not_found"):
                        vt_score = t("no_records")
                    else:
                        vt_score = result_vt.get("score", "-")
                    ibm_score = "-"
                    if self.ibm_var_url.get() and not self.stop_flag:
                        driver = self.driver_pool.get()
                        try:
                            ibm_score = check_url_ibm(driver, url)
                            if isinstance(ibm_score, str) and ibm_score.lower() == "unknown":
                                ibm_score = t("unknown")
                        finally:
                            self.driver_pool.put(driver)
                    if self.stop_flag:
                        break
                    alien_score, alien_link = check_url_alienvault(url)
                    vt_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                    vt_link = f"https://www.virustotal.com/gui/url/{vt_id}"
                    ibm_link = f"https://exchange.xforce.ibmcloud.com/url/{url}"
                    output, bad = self.process_url(i + 1, url, vt_score, ibm_score, vt_link, ibm_link, alien_score, alien_link, total_urls=len(url_list))
                    if bad:
                        self.bad_urls.add(url)
                    self._insert_colored(self.url_output_area, output, bad)
                    self.url_output_area.insert(tk.END, "\n")
                    self.url_output_area.see(tk.END)
                    self.currently_processing_urls.discard(url)
                    self.update_status_label_url()
                    if self.ibm_var_url.get():
                        self.results_url.append([url, vt_score, ibm_score, alien_score, vt_link, ibm_link, alien_link])
                    else:
                        self.results_url.append([url, vt_score, alien_score, vt_link, alien_link])
                    if self.check_ips_var_url.get() and not self.stop_flag:
                        domain = url
                        resolved_ips = self._resolve_domain_via_google_dns(domain)
                        if not resolved_ips:
                            resolved_ips = self._resolve_domain_with_socket(domain)
                        resolved_ips = sorted(set(resolved_ips))
                        if resolved_ips:
                            self.url_output_area.insert(tk.END, f"[{domain}] {t('domain_ips')}: {', '.join(resolved_ips)}\n\n")
                        else:
                            self.url_output_area.insert(tk.END, f"[{domain}] {t('domain_no_ip')}\n\n")
                        self.ip_results_by_domain[domain] = []
                        for j, ip in enumerate(resolved_ips, 1):
                            if self.stop_flag:
                                break
                            ip_output, ip_bad, ip_csv_data = self.process_url_ip_associated(ip, domain)
                            ip_output = ip_output.lstrip("\n")
                            self._insert_colored(self.url_output_area, ip_output, ip_bad)
                            self.url_output_area.insert(tk.END, "\n")
                            self.url_output_area.see(tk.END)
                            if ip_bad:
                                self.bad_urls.add(f"{ip} (associado ao Domínio)")
                            if ip_csv_data:
                                self.ip_results_by_domain[domain].append(ip_csv_data)
                if not self.stop_flag:
                    self._append_analysis_url()
                    messagebox.showinfo(t("done"), t("domain_scan_finished"))
            finally:
                self.scanning_url = False
                self.root.after(0, lambda: self.url_button_action.config(state="normal"))
        Thread(target=thread_run, daemon=True).start()

    def _append_analysis_url(self):
        if not self.pre_var_url.get():
            return
        if self.bad_urls:
            if self.mss_var_url.get():
                texto = t("url_bad_mss")
            else:
                texto = t("url_bad_no_mss")
        else:
            texto = t("url_clean")
        self.url_output_area.insert("1.0", texto + "\n\n")
        self.url_output_area.see("1.0")

    def update_status_label_url(self):
        if self.currently_processing_urls:
            inline = " | ".join(sorted(self.currently_processing_urls))
            status = f"{t('checking_domains')}: {inline}"
        else:
            status = ""
        self.url_status_label.config(text=status)

    def copy_url_output(self):
        pyperclip.copy(self.url_output_area.get("1.0", tk.END))

    def cancel_check_url(self):
        self.stop_flag = True
        self.url_status_label.config(text=f"❌ {t('scan_cancelled')}")
        self.scanning_url = False
        self.url_button_action.config(state="normal")
    def process_url(self, index, url, vt_score, ibm_score, vt_link, ibm_link, alien_score, alien_link, total_urls=1):
        reputation = t("reputation_clean")
        try:
            is_malicious = False
            
            try:
                vt_val = int(vt_score)
            except (ValueError, TypeError):
                vt_val = 0
            if vt_val > 0:
                is_malicious = True
            try:
                ibm_val = float(ibm_score)
                if ibm_val >= 2:
                    is_malicious = True
            except (ValueError, TypeError):
                if isinstance(ibm_score, str) and ibm_score.strip().lower() in ("high", "medium"):
                    is_malicious = True
            if alien_score and alien_score.strip().lower() not in ("clean", "-", "unknown", "0"):
                is_malicious = True
            if is_malicious:
                reputation = t("reputation_bad")
        except Exception:
            reputation = t("unknown")
        # Se só tiver uma URL, mostra [domínio]
        if total_urls == 1:
            first_line = f"[{url}] - {reputation}"
        else:
            first_line = f"[{index}] {url} - {reputation}"

        lines = [first_line, f"{t('vt_score')}: {vt_score}"]
        if self.ibm_var_url.get():
            lines.append(f"IBM X-Force score: {ibm_score}")
        lines.append(f"AlienVault score: {alien_score}")
        lines.append(f"- {vt_link}")
        if self.ibm_var_url.get():
            lines.append(f"- {ibm_link}")
        lines.append(f"- {alien_link}")

        is_bad = is_malicious
        return "\n".join(lines), is_bad

    def process_hash(self, h, index, total_hashes=1):
        from ip_checker_core import check_hash_alienvault
        vt_link = f"https://www.virustotal.com/gui/file/{h}"
        ibm_link = f"https://exchange.xforce.ibmcloud.com/malware/{h}"
        alien_link = f"https://otx.alienvault.com/indicator/file/{h}"
        ibm_score = "-"
        alien_score = "-"
        reputation = t("no_records")
        include_ibm = self.ibm_var_hash.get()

        # IBM
        if include_ibm:
            driver = self.driver_pool.get()
            try:
                _, ibm_score = check_hash_ibm(driver, h)
                if ibm_score and ibm_score.strip().lower() == "unknown":
                    ibm_score = t("unknown")
            finally:
                self.driver_pool.put(driver)

            if isinstance(ibm_score, str) and ibm_score.strip().lower() in ("high", "medium"):
                reputation = t("reputation_bad")

        # AlienVault
        alien_score, alien_link = check_hash_alienvault(h)

        # VirusTotal
        result = check_hash_virustotal(h)
        if not result or "data" not in result or "attributes" not in result["data"]:
            vt_score = t("no_records")
            name = "-"
            data_fmt = "N/A"
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
                reputation = t("reputation_bad")
            else:
                reputation = t("reputation_clean")
        # Joe Sandbox
        joe_found = False
        joe_link  = f"https://www.joesandbox.com/analysis/search?q={h}"
        driver = self.driver_pool.get()
        try:
            joe_found, joe_link = check_hash_joesandbox(driver, h)
        finally:
            self.driver_pool.put(driver)
        if include_ibm:
            self.results_hash.append([h, vt_score, ibm_score, alien_score, name, data_fmt, vt_link, ibm_link, alien_link, joe_link])
        else:
            self.results_hash.append([h, vt_score, alien_score, name, data_fmt, vt_link, alien_link, joe_link])
        if total_hashes == 1:
            first = f"[{h}] - {reputation}"
        else:
            first = f"[{index}] {h} - {reputation}"
        if joe_found:
            first += f" - {t('joesandbox_found')}"
        output_lines = [first, f"{t('vt_score')}: {vt_score}"]
        if include_ibm:
            output_lines.append(f"{t('ibm_score')}: {ibm_score}")
        output_lines.append(f"{t('alien_score')}: {alien_score}")
        output_lines.append(f"{t('file_name')}: {name}")
        output_lines.append(f"{t('last_analysis_vt')}: {data_fmt}")
        output_lines.append(f"- {vt_link}")
        if include_ibm:
            output_lines.append(f"- {ibm_link}")
        output_lines.append(f"- {alien_link}")
        if joe_found:
            output_lines.append(f"- {joe_link}")        
        try:
            vt_numeric = float(vt_score)
        except (ValueError, TypeError):
            vt_numeric = 0
        malicious = vt_numeric > 0 or reputation == t("reputation_bad")
        return "\n".join(output_lines) + "\n", malicious

    def cancel_check(self):
        self.stop_flag = True
        self.status_label.config(text=f"❌ {t('scan_cancelled')}")
        self.scanning_ip = False
        self.check_button.config(state="normal")
    def update_status_label(self):
        if self.currently_processing:
            inline = " | ".join(sorted(self.currently_processing))
            status = f"{t('checking_ips')}: {inline}"
        else:
            status = ""
        self.status_label.config(text=status)

    def cancel_check_hash(self):
        self.stop_flag = True
        self.hash_status_label.config(text=f"❌ {t('scan_cancelled')}")
        self.scanning_hash = False
        self.hash_button_action.config(state="normal")
    def update_status_label_hash(self):
        if self.currently_processing_hashes:
            inline = " | ".join(sorted(self.currently_processing_hashes))
            status = f"{t('checking_hashes')}: {inline}"
        else:
            status = ""
        self.hash_status_label.config(text=status)

    def copy_output(self):
        pyperclip.copy(self.output_area.get("1.0", tk.END))

    def copy_hash_output(self):
        pyperclip.copy(self.hash_output_area.get("1.0", tk.END))

    def save_results(self):
        if not self.results_ip:
            messagebox.showwarning(t("done"), t("no_results"))
            return
        headers = [
            t("csv_ip"),t("csv_abuse_score"),t("csv_vt_score"),
            *( [t("csv_ibm_score")] if self.ibm_var_ip.get() else [] ),
            t("csv_domain"),t("csv_country"),t("csv_city"),t("csv_last_report"),
            t("csv_abuse_link"),t("csv_vt_link"),
            *( [t("csv_ibm_link")] if self.ibm_var_ip.get() else [] ),
        ]

        save_to_csv(self.results_ip, headers, filename="ip_results.csv")

    def save_hash_results(self):
        if not self.results_hash:
            messagebox.showwarning(t("done"), t("no_results"))
            return

        headers = [
            t("csv_hash"),
            t("csv_vt_score"),
            *( [t("csv_ibm_score")] if self.ibm_var_hash.get() else [] ),
            t("csv_alien_score"),
            t("csv_file_name"),
            t("csv_last_analysis"),
            t("csv_vt_link"),
            *( [t("csv_ibm_link")] if self.ibm_var_hash.get() else [] ),
            t("csv_alien_link"),
            t("csv_joe_link"),
        ]   

        save_to_csv(self.results_hash, headers, filename="hash_results.csv")

    def save_url_results(self):
        if not self.results_url:
            messagebox.showwarning(t("done"), t("no_results"))
            return
        from ip_checker_core import save_to_excel
        domain_headers = [
            t("csv_domain"), t("csv_vt_score"),
            *([t("csv_ibm_score")] if self.ibm_var_url.get() else []),
            t("csv_alien_score"), t("csv_vt_link"),
            *([t("csv_ibm_link")] if self.ibm_var_url.get() else []),
            t("csv_alien_link"),
        ]
        ip_headers = [
            t("csv_ip"), t("csv_abuse_score"), t("csv_vt_score"),
            *([t("csv_ibm_score")] if self.ibm_var_url.get() else []),
            t("csv_domain"), t("csv_country"), t("csv_city"), t("csv_last_report"),
            t("csv_abuse_link"), t("csv_vt_link"),
            *([t("csv_ibm_link")] if self.ibm_var_url.get() else []),
        ]
        save_to_excel(
            domain_results=self.results_url,
            domain_headers=domain_headers,
            ip_results_by_domain=self.ip_results_by_domain,
            ip_headers=ip_headers,
            filename="domain_results.xlsx"
        )
    def run_check(self):
        if self.scanning_ip:
            messagebox.showwarning(t("done"), t("scan_already_running_ip"))
            return
        self.stop_flag = False
        self.bad_ips = set()
        self.currently_processing.clear()
        self.update_status_label()
        self.output_area.delete("1.0", tk.END)
        raw_ips = self.entry.get()
        cleaned_input = re.sub(r"[\s\n]+", ",", raw_ips)
        ips_raw_list = [ip.strip() for ip in cleaned_input.split(",") if ip.strip()]
        ips = []
        for ip in ips_raw_list:
            if not is_valid_ip(ip):
                self.output_area.insert(tk.END, f"{ip} - {t('invalid_ip')}\n")
                continue
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                self.output_area.insert(tk.END, f"{ip} - {t('private_ip')}\n")
                continue
            ips.append(ip)
        if not ips:
            messagebox.showerror(t("error"), t("no_valid_public_ip"))
            return
        self.results_ip = []
        self.scanning_ip = True
        self.check_button.config(state="disabled")
        Thread(target=self._check_ips_thread, args=(ips,), daemon=True).start()

    def _check_ips_thread(self, ips):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        def process_ip(index, ip):
            if self.stop_flag:
                return None
            self.root.after(0, lambda ip=ip: self.currently_processing.add(ip))
            self.root.after(0, self.update_status_label)
            if self.stop_flag:
                return None
            abuseipdb_result = check_ip_abuseipdb(ip)
            if self.stop_flag:
                return None
            virustotal_result = check_ip_virustotal(ip)
            if self.stop_flag:
                return None
            city, country = get_location(ip)
            domain = get_domain_from_abuseipdb(abuseipdb_result)
            ibm_score = None
            if self.ibm_var_ip.get() and not self.stop_flag:
                driver = self.driver_pool.get()
                try:
                    _, ibm_score = check_ip_ibm(driver, ip)
                    if ibm_score is not None and str(ibm_score).strip().lower() == "unknown":
                        ibm_score = t("unknown")
                finally:
                    self.driver_pool.put(driver)
            if self.stop_flag:
                return None
            data = build_ip_result(
                ip=ip,
                abuseipdb_result=abuseipdb_result,
                virustotal_result=virustotal_result,
                ibm_score=ibm_score,
                city=city,
                country=country,
                domain=domain
            )
            terminal_output = format_ip_output_gui(data, index=index, total=len(ips))
            if self.ibm_var_ip.get():
                csv_data = [
                    ip, f"{data['abuse_score']}%", data['vt_score'], data['ibm_score'] or "",
                    data['domain'], data['country'], data['city'], data['last_report'] or t("no_reports"),
                    data['links']['abuse'], data['links']['vt'], data['links']['ibm'] or ""
                ]
            else:
                csv_data = [
                    ip, f"{data['abuse_score']}%", data['vt_score'],
                    data['domain'], data['country'], data['city'], data['last_report'] or t("no_reports"),
                    data['links']['abuse'], data['links']['vt']
                ]
            bad = data["status"] == "bad"
            return (index, csv_data, terminal_output, ip, bad)
        try:
            results_buffer = []
            with ThreadPoolExecutor(max_workers=min(len(ips), 10)) as executor:
                futures = {executor.submit(process_ip, i + 1, ip): i for i, ip in enumerate(ips)}
                for future in as_completed(futures):
                    if self.stop_flag:
                        for f in futures:
                            f.cancel()
                        break
                    try:
                        result = future.result(timeout=1)
                        if result:
                            results_buffer.append(result)
                            results_buffer.sort(key=lambda x: x[0])
                            self.root.after(0, lambda: self.refresh_ip_output(results_buffer.copy()))
                    except Exception as e:
                        if not self.stop_flag:
                            self.root.after(0, lambda e=e: self.output_area.insert(tk.END, f"Erro ao processar IP: {e}\n"))
            if not self.stop_flag:
                self.root.after(0, lambda: messagebox.showinfo(t("done"), t("scan_finished")))
        finally:
            self.scanning_ip = False
            self.root.after(0, lambda: self.check_button.config(state="normal"))

    def refresh_ip_output(self, sorted_results):
        self.output_area.delete("1.0", tk.END)
        self.results_ip.clear()
        for index, csv_data, terminal_output, ip, bad in sorted_results:
            if bad:
                self.bad_ips.add(ip)
            self.results_ip.append(csv_data)
            self._insert_colored(self.output_area, terminal_output, bad)
            self.output_area.insert(tk.END, "\n")
            self.output_area.see(tk.END)
            self.currently_processing.discard(ip)
        self.update_status_label()
        if not self.currently_processing:
            self._append_analysis()

    def _append_analysis(self):
        if not self.pre_var_ip.get():
            return
        if self.bad_ips:
            lista = ",".join(sorted(self.bad_ips))
            if self.mss_var_ip.get():
                texto = t("ip_bad_mss").format(lista=lista)
            else:
                texto = t("ip_bad_no_mss").format(lista=lista)
        else:
            texto = t("ip_clean")
        self.output_area.insert("1.0", texto + "\n\n")
        self.output_area.see("1.0")

    def process_url_ip_associated(self, ip, domain):
        try:
            abuseipdb_result = check_ip_abuseipdb(ip)
            virustotal_result = check_ip_virustotal(ip)
            city, country = get_location(ip)
            assoc_domain = get_domain_from_abuseipdb(abuseipdb_result)
            ibm_score = None
            if self.ibm_var_url.get():
                driver = self.driver_pool.get()
                try:
                    _, ibm_score = check_ip_ibm(driver, ip)
                    if ibm_score is not None and str(ibm_score).strip().lower() == "unknown":
                        ibm_score = t("unknown")
                finally:
                    self.driver_pool.put(driver)
            data = build_ip_result(
                ip=ip,
                abuseipdb_result=abuseipdb_result,
                virustotal_result=virustotal_result,
                ibm_score=ibm_score,
                city=city,
                country=country,
                domain=assoc_domain
            )
            terminal_output = format_ip_output_gui(data)
            bad = data["status"] == "bad"
            if self.ibm_var_url.get():
                csv_data = [
                    ip, f"{data['abuse_score']}%", data['vt_score'], data['ibm_score'] or "",
                    data['domain'], data['country'], data['city'], data['last_report'] or t("no_reports"),
                    data['links']['abuse'], data['links']['vt'], data['links']['ibm'] or ""
                ]
            else:
                csv_data = [
                    ip, f"{data['abuse_score']}%", data['vt_score'],
                    data['domain'], data['country'], data['city'], data['last_report'] or t("no_reports"),
                    data['links']['abuse'], data['links']['vt']
                ]
            return terminal_output, bad, csv_data
        except Exception as e:
            return f"{t('error_checking_associated_ip')} {ip}: {e}", False, None

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
            drivers_to_close = set(self.all_drivers)
            while not self.driver_pool.empty():
                drivers_to_close.add(self.driver_pool.get_nowait())
            def _quit(d):
                try:
                    d.quit()
                except Exception:
                    pass
            with ThreadPoolExecutor(max_workers=len(drivers_to_close) or 1) as executor:
                executor.map(_quit, drivers_to_close)
        except Exception as e:
            print(f"Erro ao fechar drivers: {e}")
        finally:
            self.root.destroy()

import webbrowser
from tkinter import Toplevel, Label, Button

def show_update_window(latest_version, novidades_texto):
    update_win = Toplevel()
    update_win.title(t("update_available"))
    update_win.configure(bg="#1e1e1e")
    update_win.geometry("500x300")
    Label(update_win, text=t("new_version_available").format(version=latest_version),
          bg="#1e1e1e", fg="white", font=("Segoe UI", 10, "bold")).pack(pady=(10, 5))
    Label(update_win, text=t("whats_new"), bg="#1e1e1e", fg="white", anchor="w",
          font=("Segoe UI", 10, "underline")).pack(pady=(5, 0), anchor="w", padx=10)
    novidades_lines = novidades_texto.strip().splitlines() if novidades_texto else [t("cannot_load_release_notes")]
    for item in novidades_lines:
        Label(update_win, text="• " + item.strip(), bg="#1e1e1e", fg="white", anchor="w",
              font=("Segoe UI", 10)).pack(anchor="w", padx=20)
    def open_github():
        webbrowser.open("https://github.com/alexsilva-sh/IP-Shark/releases")
    link_label = Label(update_win, text=t("download_github"),
                       fg="#00aaff", bg="#1e1e1e", cursor="hand2", font=("Segoe UI", 10, "bold"))
    link_label.pack(pady=20)
    link_label.bind("<Button-1>", lambda e: open_github())

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
    style.configure("Nav.TButton",background="#333333",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.map("Nav.TButton",background=[("active","#444444")])
    style.configure("NavActive.TButton",background="#007acc",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.theme_use("clam")
    style.configure("Nav.TButton",background="#333333",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.map("Nav.TButton",background=[("active","#444444")])
    style.configure("NavActive.TButton",background="#007acc",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.configure("Secondary.TButton",background="#333333",foreground="white",font=("Segoe UI",10),padding=(10,5))
    style.map("Secondary.TButton",background=[("active","#222222"),("pressed","#1a1a1a")],foreground=[("active","white")])
    style.map("Danger.TButton",background=[("active","#7a0000"),("pressed","#5c0000")],foreground=[("active","white")])
    style.configure("Danger.TButton",background="#aa0000",foreground="white",font=("Segoe UI",10,"bold"),padding=(10,5))
    style.configure("Custom.TEntry",fieldbackground="#2a2a2a",foreground="white",padding=6)
    style.configure("Status.TLabel",background="#1e1e1e",foreground="#00c853",font=("Segoe UI",9))
    style.configure("Title.TLabel",background="#1e1e1e",foreground="white",font=("Segoe UI",11,"bold"))
    style.configure("Primary.TButton",background="#007acc",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.map("Primary.TButton",background=[("active","#1e90ff"),("pressed","#0060a8")],foreground=[("active","white")])
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

    latest, novidades = check_latest_version()
    if latest:
        show_update_window(latest, novidades)
    app = IPCheckerApp(root)
    app._register_i18n(btn_config, "btn_config_api")
    update_language_buttons()
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()