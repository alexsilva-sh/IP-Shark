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

__version__ = "v2.4.8"

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

from ip_checker_core import (
    is_valid_ip,
    check_ip_abuseipdb,
    check_ip_virustotal,
    check_ip_ibm,
    start_browser,
    get_location,
    get_domain_from_abuseipdb,
    format_output,
    format_terminal_output,
    save_to_csv,
    check_hash_virustotal,
    safe_get
)

def is_valid_hash(h):
    h = h.lower()
    return (
        re.fullmatch(r"[a-f0-9]{32}", h) or  #MD5
        re.fullmatch(r"[a-f0-9]{40}", h) or  #SHA1
        re.fullmatch(r"[a-f0-9]{64}", h)     #SHA256
    )

class ToggleSwitch(tk.Frame):
    def __init__(self, master, text="", variable=None,
                 on_bg="#34C759", off_bg="#444444",
                 width=42, height=22,
                 state="normal",
                 **kwargs):
        super().__init__(master, bg=master["bg"], **kwargs)

        self.var = variable or tk.BooleanVar(value=False)
        self.state = state
        self.on_bg  = on_bg
        self.off_bg = off_bg
        self.canvas = tk.Canvas(self, width=width, height=height, highlightthickness=0, bg=master["bg"])
        self.canvas.pack(side="left")
        self.label = tk.Label(self, text=text, fg="white", bg=master["bg"], anchor="w")
        self.label.pack(side="left", padx=(6, 0))
        radius = height // 2 - 2
        self.track = self.canvas.create_rectangle(2, 2, width-2, height-2, outline="", fill=off_bg)
        self.knob  = self.canvas.create_oval(2, 2, 2+2*radius, 2+2*radius, outline="", fill="white")
        self.canvas.bind("<Button-1>", self._toggle)
        self.label .bind("<Button-1>", self._toggle)
        self._update_position()
        if self.state == "disabled":
            self._gray()

    def set_state(self, state):
        self.state = state
        if state == "disabled":
            self._gray()
        else:
            self._restore()

    def _toggle(self, _evt=None):
        if self.state == "disabled":
            return
        self.var.set(not self.var.get())
        self._update_position()

    def _update_position(self):
        width  = int(self.canvas["width"])
        height = int(self.canvas["height"])
        radius = height // 2 - 2
        if self.var.get():
            self.canvas.itemconfig(self.track, fill=self.on_bg)
            x0 = width - 2 - 2*radius
        else:
            self.canvas.itemconfig(self.track, fill=self.off_bg)
            x0 = 2
        self.canvas.coords(self.knob, x0, 2, x0+2*radius, 2+2*radius)

    def _gray(self):
        self.label.config(fg="#666666")
        self.canvas.itemconfig(self.track, fill="#2f2f2f")
        self.canvas.itemconfig(self.knob,  fill="#666666")

    def _restore(self):
        self.label.config(fg="white")
        self._update_position()

class IPCheckerApp:
    def __init__(self, root):
        self.currently_processing = set()
        self.root = root
        root.title(f"IP Shark {__version__} - by @alexsilva.sh in Github")
        self.root.configure(bg="#1e1e1e")
        self.tab_frame = tk.Frame(self.root, bg="#1e1e1e")
        self.tab_frame.pack(pady=(5, 0))
        self.ip_button = tk.Button(self.tab_frame, text="Consulta IP", command=self.show_ip_page,
                                   bg="#007acc", fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT)
        self.ip_button.grid(row=0, column=0, padx=5)
        self.hash_button = tk.Button(self.tab_frame, text="Consulta Hash", command=self.show_hash_page,
                                     bg="#333333", fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT)
        self.hash_button.grid(row=0, column=1, padx=5)
        self.page_ip = tk.Frame(root, bg="#1e1e1e")
        self.page_ip.pack(fill=tk.BOTH, expand=True)
        self.page_hash = tk.Frame(root, bg="#1e1e1e")
        self.page_hash.pack_forget()
        self.driver_pool = Queue()
        for _ in range(3): #ou outro limite seguro
            self.driver_pool.put(start_browser())
            self.all_drivers = list(self.driver_pool.queue)
        label_font = ("Segoe UI", 10)
        entry_font = ("Consolas", 10)
        button_font = ("Segoe UI", 10, "bold")
        self.input_label = tk.Label(self.page_ip, text="Cole os IPs (separados por espaço, quebra de linha ou vírgula):", bg="#1e1e1e", fg="white", font=label_font)
        self.input_label.pack(pady=(10, 2))
        self.entry = tk.Entry(self.page_ip, width=90, bg="#2d2d2d", fg="white", insertbackground='white', font=entry_font, relief=tk.FLAT)
        self.entry.pack(pady=5, padx=10, ipady=4)
        
        toggles_ip = tk.Frame(self.page_ip, bg="#1e1e1e")
        toggles_ip.pack(pady=6)

        self.ibm_var_ip = tk.BooleanVar(value=True)
        ToggleSwitch(toggles_ip, text="IBM X-Force",
                     variable=self.ibm_var_ip).pack(side="left", padx=(0, 15))

        col_ip = tk.Frame(toggles_ip, bg="#1e1e1e")
        col_ip.pack(side="left")
        self.pre_var_ip = tk.BooleanVar(value=False)
        ToggleSwitch(col_ip, text="Pré análise",
                     variable=self.pre_var_ip).pack(anchor="w")

        self.mss_var_ip = tk.BooleanVar(value=False)
        self.mss_ip_switch = ToggleSwitch(col_ip, text="Cliente tem MSS?", variable=self.mss_var_ip, state="disabled")
        self.mss_ip_switch.pack(anchor="w")

        self.pre_var_ip.trace_add("write", self._update_mss_state_ip)     
        self.check_button = tk.Button(self.page_ip, text="🔍 Consultar IP(s)", command=self.run_check, bg="#007acc", fg="white",
                                      font=button_font, relief=tk.FLAT, activebackground="#005f99")
        self.check_button.pack(pady=10)
        self.status_label = tk.Label(self.page_ip, text="", bg="#1e1e1e", fg="#00ff99", font=label_font)
        self.status_label.pack()
        self.output_area = scrolledtext.ScrolledText(self.page_ip, wrap=tk.NONE, width=120, height=30, bg="#1e1e1e", fg="white", font=entry_font, insertbackground='white')
        self.output_area.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
        self.button_frame = tk.Frame(self.page_ip, bg="#1e1e1e")
        self.button_frame.pack(pady=(0, 10))
        self.copy_button = tk.Button(self.button_frame, text="Copiar Resultado", command=self.copy_output, bg="#333333", fg="white", font=label_font, relief=tk.FLAT)
        self.copy_button.grid(row=0, column=0, padx=10)
        self.save_button = tk.Button(self.button_frame, text="Exportar para CSV", command=self.save_results, bg="#333333", fg="white", font=label_font, relief=tk.FLAT)
        self.save_button.grid(row=0, column=1, padx=10)
        self.cancel_button = tk.Button(self.button_frame, text="🛑 Interromper Consulta", command=self.cancel_check,
                                       bg="#aa0000", fg="white", font=label_font, relief=tk.FLAT)
        self.cancel_button.grid(row=0, column=2, padx=10)
        self.results = []
        self.results_url = []
        self.stop_flag = False

        # Conteúdo da aba HASH
        self.input_label_hash = tk.Label(self.page_hash, text="Cole os hashes (separados por espaço, quebra de linha ou vírgula):", bg="#1e1e1e", fg="white", font=label_font)
        self.input_label_hash.pack(pady=(10, 2))
        self.hash_entry = tk.Entry(self.page_hash, width=90, bg="#2d2d2d", fg="white",
                                   insertbackground='white', font=entry_font, relief=tk.FLAT)
        self.hash_entry.pack(pady=5, padx=10, ipady=4)
        self.ibm_var_hash = tk.BooleanVar(value=True)
        
        # ---------- interruptores (aba HASH) ---------------------------
        toggles_hash = tk.Frame(self.page_hash, bg="#1e1e1e")
        toggles_hash.pack(pady=6)

        self.ibm_var_hash = tk.BooleanVar(value=True)
        ToggleSwitch(toggles_hash, text="IBM X-Force",
                     variable=self.ibm_var_hash).pack(side="left", padx=(0, 15))

        col_hash = tk.Frame(toggles_hash, bg="#1e1e1e")
        col_hash.pack(side="left")

        self.pre_var_hash = tk.BooleanVar(value=False)
        ToggleSwitch(col_hash, text="Pré análise",
                     variable=self.pre_var_hash).pack(anchor="w")

        self.mss_var_hash = tk.BooleanVar(value=False)
        self.mss_hash_switch = ToggleSwitch(col_hash, text="Cliente tem MSS?", variable=self.mss_var_hash, state="disabled")
        self.mss_hash_switch.pack(anchor="w")
        self.pre_var_hash.trace_add("write", self._update_mss_state_hash)        
        self.hash_button_action = tk.Button(self.page_hash, text="🔍 Consultar Hash", command=self.run_hash_check, bg="#007acc", fg="white", font=button_font, relief=tk.FLAT)
        self.hash_button_action.pack(pady=10)
        self.currently_processing_hashes = set()
        self.hash_status_label = tk.Label(self.page_hash, text="", bg="#1e1e1e", fg="#00ff99", font=label_font)
        self.hash_status_label.pack()
        self.hash_output_area = scrolledtext.ScrolledText(self.page_hash, wrap=tk.NONE, width=120, height=30, bg="#1e1e1e", fg="white", font=entry_font, insertbackground='white')
        self.hash_output_area.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
        self.hash_button_frame = tk.Frame(self.page_hash, bg="#1e1e1e")
        self.hash_button_frame.pack(pady=(0, 10))
        self.hash_copy_button = tk.Button(self.hash_button_frame, text="Copiar Resultado", command=self.copy_hash_output, bg="#333333", fg="white", font=label_font, relief=tk.FLAT)
        self.hash_copy_button.grid(row=0, column=0, padx=10)
        self.hash_save_button = tk.Button(self.hash_button_frame, text="Exportar para CSV", command=self.save_hash_results, bg="#333333", fg="white", font=label_font, relief=tk.FLAT)
        self.hash_save_button.grid(row=0, column=1, padx=10)
        self.hash_cancel_button = tk.Button(self.hash_button_frame, text="🛑 Interromper Consulta", command=self.cancel_check_hash, bg="#aa0000", fg="white", font=label_font, relief=tk.FLAT)
        self.hash_cancel_button.grid(row=0, column=2, padx=10)
    
        # Conteúdo da aba Domínio
        self.url_button = tk.Button(self.tab_frame, text="Consulta Domínio", command=self.show_url_page, bg="#333333", fg="white", font=("Segoe UI", 10, "bold"), relief=tk.FLAT)
        self.url_button.grid(row=0, column=2, padx=5)
        self.page_url = tk.Frame(root, bg="#1e1e1e")
        self.page_url.pack_forget()
        self.input_label_url = tk.Label(self.page_url, text="Cole os domínios (separados por espaço, quebra de linha ou vírgula):", bg="#1e1e1e", fg="white", font=label_font)
        self.input_label_url.pack(pady=(10, 2))
        self.url_entry = tk.Entry(self.page_url, width=90, bg="#2d2d2d", fg="white", insertbackground='white', font=entry_font, relief=tk.FLAT)
        self.url_entry.pack(pady=5, padx=10, ipady=4)

        toggles_url = tk.Frame(self.page_url, bg="#1e1e1e")
        toggles_url.pack(pady=6)
        self.ibm_var_url = tk.BooleanVar(value=True)
        ToggleSwitch(toggles_url, text="IBM X-Force", variable=self.ibm_var_url).pack(side="left", padx=(0, 15))
        col_url = tk.Frame(toggles_url, bg="#1e1e1e")
        col_url.pack(side="left")
        self.pre_var_url = tk.BooleanVar(value=False)
        ToggleSwitch(col_url, text="Pré análise", variable=self.pre_var_url).pack(anchor="w")
        self.mss_var_url = tk.BooleanVar(value=False)
        self.mss_url_switch = ToggleSwitch(col_url, text="Cliente tem MSS?", variable=self.mss_var_url, state="disabled")
        self.mss_url_switch.pack(anchor="w")
        self.pre_var_url.trace_add("write", self._update_mss_state_url)
        self.url_button_action = tk.Button(self.page_url, text="🔍 Consultar Domínio", command=self.run_url_check, bg="#007acc", fg="white", font=button_font, relief=tk.FLAT)
        self.url_button_action.pack(pady=10)
        self.url_status_label = tk.Label(self.page_url, text="", bg="#1e1e1e", fg="#00ff99", font=label_font)
        self.url_status_label.pack()
        self.url_output_area = scrolledtext.ScrolledText(self.page_url, wrap=tk.NONE, width=120, height=30, bg="#1e1e1e", fg="white", font=entry_font, insertbackground='white')
        self.url_output_area.pack(padx=10, pady=(0, 10), fill=tk.BOTH, expand=True)
        self.url_button_frame = tk.Frame(self.page_url, bg="#1e1e1e")
        self.url_button_frame.pack(pady=(0, 10))
        self.url_copy_button = tk.Button(self.url_button_frame, text="Copiar Resultado", command=self.copy_url_output, bg="#333333", fg="white", font=label_font, relief=tk.FLAT)
        self.url_copy_button.grid(row=0, column=0, padx=10)
        self.url_save_button = tk.Button(self.url_button_frame, text="Exportar para CSV", command=self.save_url_results, bg="#333333", fg="white", font=label_font, relief=tk.FLAT)
        self.url_save_button.grid(row=0, column=1, padx=10)
        self.url_cancel_button = tk.Button(self.url_button_frame, text="🛑 Interromper Consulta", command=self.cancel_check_url, bg="#aa0000", fg="white", font=label_font, relief=tk.FLAT)
        self.url_cancel_button.grid(row=0, column=2, padx=10)        
        self.currently_processing_urls = set()

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
        self.ip_button.config(bg="#007acc")
        self.hash_button.config(bg="#333333")
        self.url_button.config(bg="#333333")

    def show_hash_page(self):
        self.page_ip.pack_forget()
        self.page_url.pack_forget()
        self.page_hash.pack(fill=tk.BOTH, expand=True)
        self.ip_button.config(bg="#333333")
        self.hash_button.config(bg="#007acc")
        self.url_button.config(bg="#333333")

    def show_url_page(self):
        self.page_ip.pack_forget()
        self.page_hash.pack_forget()
        self.page_url.pack(fill=tk.BOTH, expand=True)
        self.ip_button.config(bg="#333333")
        self.hash_button.config(bg="#333333")
        self.url_button.config(bg="#007acc")

    def run_hash_check(self):
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
            messagebox.showwarning("Hashes Inválidos", "Os seguintes hashes são inválidos:\n" + "\n".join(invalid_hashes))

        if not hash_list:
            messagebox.showerror("Erro", "Nenhum hash válido informado.")
            return
        self.results = []
        self.results_url = []
        self.stop_flag = False
        self.currently_processing_hashes.clear()
        self.update_status_label_hash()

        def thread_run():
            for i, h in enumerate(hash_list):
                self.currently_processing_hashes.add(h)
                self.update_status_label_hash()

                if self.stop_flag:
                    self.hash_output_area.insert(tk.END, f"[CANCELADO] {h}\n")
                    self.currently_processing_hashes.discard(h)
                    self.update_status_label_hash()
                    break
                result_text, bad = self.process_hash(h, i + 1, total_hashes=len(hash_list))
                if bad:
                    self.bad_hashes.add(h)
                self.hash_output_area.insert(tk.END, result_text + "\n")
                self.hash_output_area.see(tk.END)
                
                self.currently_processing_hashes.discard(h)
                self.update_status_label_hash()
            self._append_analysis_hash()
            messagebox.showinfo("Concluído", "Consulta de hashes finalizada.")
        Thread(target=thread_run, daemon=True).start()

    def _append_analysis_hash(self):
        if not self.pre_var_hash.get():
            return
        if self.bad_hashes:
            if self.mss_var_hash.get():
                texto = ("Arquivo malicioso detectado.\n"
                         "Um chamado foi aberto com o MSS para que um full scan seja efetuado no host: ")
            else:
                texto = ("Arquivo malicioso detectado.\n"
                         "Recomendamos a execução de um full scan no host para eliminar quaisquer vestígios de malware.")
        else:
            texto = ("Nenhum indício de reputação maliciosa foi encontrado para o hash consultado.")
        self.hash_output_area.insert("1.0", texto + "\n\n")
        self.hash_output_area.see("1.0")

    def run_url_check(self):
            self.results_url.clear()
            self.bad_urls = set()
            from ip_checker_core import check_url_virustotal, check_url_ibm
            self.url_output_area.delete("1.0", tk.END)
            
            raw_urls = self.url_entry.get()
            cleaned_urls = re.sub(r"[\s\n]+", ",", raw_urls)
            url_list = [u.strip() for u in cleaned_urls.split(",") if u.strip()]

            if not url_list:
                messagebox.showerror("Erro", "Nenhum domínio informado.")
                return
                
            self.stop_flag = False
            self.currently_processing_urls.clear()
            self.update_status_label_url()

            def thread_run():
                for i, raw_url in enumerate(url_list):
                    temp_url_for_parse = raw_url
                    if not re.match(r'^\w+://', temp_url_for_parse):
                        temp_url_for_parse = 'http://' + temp_url_for_parse
                    
                    try:
                        parsed_initial = urlparse(temp_url_for_parse)
                        # Pega o netloc (ex: www.site.com) e remove porta se houver (split :)
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
                        self.url_output_area.insert(tk.END, f"[CANCELADO] {url}\n")
                        self.currently_processing_urls.discard(url)
                        self.update_status_label_url()
                        break

                    result_vt = check_url_virustotal(url)
                    if result_vt.get("not_found"):
                        vt_score = "Sem registros"
                    else:
                        vt_score = result_vt.get("score", "-")

                    ibm_score = "-"
                    if self.ibm_var_url.get():
                        driver = self.driver_pool.get()
                        try:
                            ibm_score = check_url_ibm(driver, url)
                            if ibm_score.lower() == "unknown":
                                ibm_score = "Desconhecido"
                        finally:
                            self.driver_pool.put(driver)

                    alien_score, alien_link = check_url_alienvault(url)
                    
                    vt_id   = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
                    vt_link = f"https://www.virustotal.com/gui/url/{vt_id}"
                    # IBM muitas vezes prefere /host/ para dominios, mas /url/ costuma redirecionar bem
                    ibm_link = f"https://exchange.xforce.ibmcloud.com/url/{url}" 
                    
                    output, bad = self.process_url(i + 1, url, vt_score, ibm_score, vt_link, ibm_link, alien_score, alien_link, total_urls=len(url_list))
                    
                    if bad:
                        self.bad_urls.add(url)
                    
                    self.url_output_area.insert(tk.END, output + "\n\n")
                    self.url_output_area.see(tk.END)
                    self.currently_processing_urls.discard(url)
                    self.update_status_label_url()
                    
                    self.results_url.append([
                        url, vt_score, ibm_score, alien_score, vt_link, ibm_link, alien_link
                    ])

                    def resolve_domain_via_google_dns(domain):
                        try:
                            response = requests.get(f"https://dns.google/resolve?name={domain}&type=A", timeout=5)
                            data = response.json()
                            ips = []
                            if 'Answer' in data:
                                for answer in data['Answer']:
                                    ip = answer.get('data')
                                    if ip and is_public_ip(ip):
                                        ips.append(ip)
                            return ips
                        except Exception:
                            return []
                    def is_public_ip(ip):
                        try:
                            return ipaddress.ip_address(ip).is_global
                        except ValueError:
                            return False
                    def resolve_domain_to_ips(domain):
                        try:
                            name, alias, ips = socket.gethostbyname_ex(domain)
                            return ips
                        except Exception:
                            return []
                    domain = url 
                    resolved_ips = self._resolve_domain_via_google_dns(domain)
                    if not resolved_ips:
                        resolved_ips = self._resolve_domain_with_socket(domain)
                    
                    resolved_ips = sorted(set(resolved_ips))
                    
                    if resolved_ips:
                        self.url_output_area.insert(tk.END, f"[{domain}] IP(s) associados(s) para o domínio: {', '.join(resolved_ips)}\n\n")
                    else:
                        self.url_output_area.insert(tk.END, f"[{domain}] Não foi possível resolver IP para o domínio.\n\n")
                    
                    for j, ip in enumerate(resolved_ips, 1):
                        ip_output, ip_bad = self.process_url_ip_associated(ip, domain)
                        ip_output = ip_output.lstrip("\n")
                        self.url_output_area.insert(tk.END, ip_output + "\n\n")
                        self.url_output_area.see(tk.END)
                        if ip_bad:
                            self.bad_urls.add(f"{ip} (associado ao Domínio)")
                
                self._append_analysis_url()
                messagebox.showinfo("Concluído", "Consulta de domínio finalizada.")
            
            Thread(target=thread_run, daemon=True).start()

    def _append_analysis_url(self):
        if not self.pre_var_url.get():
            return
        if self.bad_urls:
            if self.mss_var_url.get():
                texto = ("Domínio(s) com má reputação detectada.\n"
                         "Um chamado foi aberto com o MSS para efetuar o bloqueio para o(s) Domínio(s): ")
            else:
                texto = ("Domínio(s) com má reputação detectada.\n"
                         "Recomendamos o bloqueio ou inspeção do tráfego.")
        else:
            texto = ("Nenhum indício de reputação maliciosa foi encontrado para os Domínios consultados.")
        self.url_output_area.insert("1.0", texto + "\n\n")
        self.url_output_area.see("1.0")

    def update_status_label_url(self):
        if self.currently_processing_urls:
            inline = " | ".join(sorted(self.currently_processing_urls))
            status = f"Consultando Domínios: {inline}"
        else:
            status = ""
        self.url_status_label.config(text=status)

    def copy_url_output(self):
        pyperclip.copy(self.url_output_area.get("1.0", tk.END))

    def cancel_check_url(self):
        self.stop_flag = True
        self.url_status_label.config(text="❌ Consulta interrompida pelo usuário.")

    def process_url(self, index, url, vt_score, ibm_score, vt_link, ibm_link, alien_score, alien_link, total_urls=1):
        reputation = "NÃO possui má reputação"
        try:
            is_malicious = False
            try:
                vt_val = int(vt_score)
                if vt_val > 0:
                    is_malicious = True
            except (ValueError, TypeError):
                pass
            try:
                ibm_val = float(ibm_score)
                if ibm_val >= 2:
                    is_malicious = True
            except (ValueError, TypeError):
                if isinstance(ibm_score, str) and ibm_score.strip().lower() in ("alto", "médio", "moderado"):
                    is_malicious = True
            if alien_score and alien_score.strip().lower() not in ("clean", "-", "desconhecido", "unknown", "0"):
                is_malicious = True
            if is_malicious:
                reputation = "Possui má reputação"
        except Exception:
            reputation = "Desconhecida"

        # Se só tiver uma URL, mostra [domínio]
        if total_urls == 1:
            first_line = f"[{url}] - {reputation}"
        else:
            first_line = f"[{index}] {url} - {reputation}"

        lines = [first_line, f"Score VirusTotal: {vt_score}"]
        if self.ibm_var_url.get():
            lines.append(f"IBM X-Force: {ibm_score}")
        lines.append(f"AlienVault: {alien_score}")
        lines.append(f"- {vt_link}")
        if self.ibm_var_url.get():
            lines.append(f"- {ibm_link}")
        lines.append(f"- {alien_link}")

        is_bad = "Possui má reputação" in reputation
        return "\n".join(lines), is_bad

    def process_hash(self, h, index, total_hashes=1):
        from ip_checker_core import check_hash_alienvault
        vt_link = f"https://www.virustotal.com/gui/file/{h}"
        ibm_link = f"https://exchange.xforce.ibmcloud.com/malware/{h}"
        alien_link = f"https://otx.alienvault.com/indicator/file/{h}"
        ibm_score = "-"
        alien_score = "-"
        reputation = "Sem registros"
        include_ibm = self.ibm_var_hash.get()

        # IBM
        if include_ibm:
            driver = self.driver_pool.get()
            try:
                _, ibm_score = check_hash_ibm(driver, h)
                if ibm_score and ibm_score.strip().lower() == "unknown":
                    ibm_score = "Desconhecido"
            finally:
                self.driver_pool.put(driver)

            if ibm_score and ibm_score.strip().lower() in ("alto", "médio", "moderado"):
                reputation = "Possui má reputação"

        # AlienVault
        alien_score, alien_link = check_hash_alienvault(h)

        # VirusTotal
        result = check_hash_virustotal(h)
        if not result or "data" not in result or "attributes" not in result["data"]:
            vt_score = "Sem registros"
            name = "-"
            data_fmt = "N/A"
        else:
            attrs = result["data"]["attributes"]
            name = safe_get(attrs, "meaningful_name", default="Desconhecido")
            vt_score = safe_get(attrs, "last_analysis_stats", "malicious", default=0)
            timestamp = safe_get(attrs, "last_analysis_date")
            if timestamp:
                from datetime import datetime, timezone
                data_fmt = datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime('%d/%m/%Y %H:%M:%S')
            else:
                data_fmt = "N/A"
            if vt_score > 0:
                reputation = "Possui má reputação"
            else:
                reputation = "NÃO possui má reputação"

        # Joe Sandbox -------------------------------------------------
        joe_found = False
        joe_link  = f"https://www.joesandbox.com/analysis/search?q={h}"
        driver = self.driver_pool.get()
        try:
            joe_found, joe_link = check_hash_joesandbox(driver, h)
        finally:
            self.driver_pool.put(driver)
        if include_ibm:
            self.results.append([h, vt_score, ibm_score, alien_score, name, data_fmt, vt_link, ibm_link, alien_link, joe_link])
        else:
            self.results.append([h, vt_score, alien_score, name, data_fmt, vt_link, alien_link, joe_link])
        if total_hashes == 1:
            first = f"[{h}] - {reputation}"
        else:
            first = f"[{index}] {h} - {reputation}"
        if joe_found:
            first += " - Foi encontrado relatório no JOESandbox"
        output_lines = [first,f"Score VirusTotal: {vt_score}"]
        if include_ibm:
            output_lines.append(f"Score IBM: {ibm_score}")
        output_lines.append(f"Score AlienVault: {alien_score}")
        output_lines.append(f"Nome do arquivo: {name}")
        output_lines.append(f"Última análise no VirusTotal: {data_fmt}")
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
        malicious = vt_numeric > 0 or reputation.startswith("Possui")
        return "\n".join(output_lines) + "\n", malicious

    def cancel_check(self):
        self.stop_flag = True
        self.status_label.config(text="❌ Consulta interrompida pelo usuário.")

    def update_status_label(self):
        if self.currently_processing:
            inline = " | ".join(sorted(self.currently_processing))
            status = f"Consultando IPs: {inline}"
        else:
            status = ""
        self.status_label.config(text=status)

    def cancel_check_hash(self):
        self.stop_flag = True
        self.hash_status_label.config(text="❌ Consulta interrompida pelo usuário.")

    def update_status_label_hash(self):
        if self.currently_processing_hashes:
            inline = " | ".join(sorted(self.currently_processing_hashes))
            status = f"Consultando Hashes: {inline}"
        else:
            status = ""
        self.hash_status_label.config(text=status)

    def copy_output(self):
        pyperclip.copy(self.output_area.get("1.0", tk.END))

    def copy_hash_output(self):
        pyperclip.copy(self.hash_output_area.get("1.0", tk.END))

    def save_results(self):
        if self.results:
            save_to_csv(self.results)
        else:
            messagebox.showwarning("Aviso", "Nenhum resultado para salvar.")

    def save_hash_results(self):
        if not self.results:
            messagebox.showwarning("Aviso", "Nenhum resultado para salvar.")
            return
        folder = filedialog.askdirectory(title="Selecione a pasta para salvar os resultados de hash")
        if not folder:
            return
        import os
        import csv
        file_path = os.path.join(folder, "hash_results.csv")
        try:
            with open(file_path, mode='w', newline='', encoding='utf-8-sig') as file:
                writer = csv.writer(file)
                include_ibm = self.ibm_var_hash.get()

                if include_ibm:
                    writer.writerow([
                        "Hash", "Score VT", "Score IBM", "Score AlienVault",
                        "Nome do Arquivo", "Última Análise",
                        "Link VirusTotal", "Link IBM", "Link AlienVault", "Link JoeSandbox"
                    ])
                else:
                    writer.writerow([
                        "Hash", "Score VT", "Score AlienVault",
                        "Nome do Arquivo", "Última Análise",
                        "Link VirusTotal", "Link AlienVault", "Link JoeSandbox"
                    ])
                for row in self.results:
                    writer.writerow(row)
        except Exception as e:
            messagebox.showerror("Erro ao salvar", f"Erro ao salvar CSV: {e}")

    def save_url_results(self):
        if not self.url_output_area.get("1.0", tk.END).strip():
            messagebox.showwarning("Aviso", "Nenhum resultado para salvar.")
            return
        folder = filedialog.askdirectory(title="Selecione a pasta para salvar os resultados de URL")
        if not folder:
            return
        import os
        import csv
        file_path = os.path.join(folder, "url_results.csv")
        try:
            if not self.results_url:
                messagebox.showwarning("Aviso", "Nenhum resultado para salvar.")
                return

            with open(file_path, mode='w', newline='', encoding='utf-8-sig') as file:
                writer = csv.writer(file)
                writer.writerow(["URL", "Score VT", "Score IBM", "Score AlienVault",
                                 "Link VirusTotal", "Link IBM", "Link AlienVault"])
                for row in self.results_url:
                    writer.writerow(row)
        except Exception as e:
            messagebox.showerror("Erro ao salvar", f"Erro ao salvar CSV: {e}")

    def run_check(self):
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
                self.output_area.insert(tk.END, f"{ip} - IP inválido\n")
                continue
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_private:
                self.output_area.insert(tk.END, f"{ip} - IP privado\n")
                continue
            ips.append(ip)
        if not ips:
            messagebox.showerror("Erro", "Nenhum IP público válido informado.")
            return
        self.results = []
        Thread(target=self._check_ips_thread, args=(ips,), daemon=True).start()

    def _check_ips_thread(self, ips):
        from concurrent.futures import ThreadPoolExecutor, as_completed
        def process_ip(index, ip):
            if self.stop_flag:
                return None
            self.root.after(0, lambda: self.currently_processing.add(ip))
            self.root.after(0, self.update_status_label)
            abuseipdb_result = check_ip_abuseipdb(ip)
            virustotal_result = check_ip_virustotal(ip)
            city, country = get_location(ip)
            domain = get_domain_from_abuseipdb(abuseipdb_result)
            ibm_score = None
            if self.ibm_var_ip.get():
                driver = self.driver_pool.get()
                try:
                    _, ibm_score = check_ip_ibm(driver, ip)
                    if ibm_score is not None and str(ibm_score).strip().lower() == "unknown":
                        ibm_score = "Desconhecido"
                finally:
                    self.driver_pool.put(driver)
            csv_data = format_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index)
            terminal_output = format_terminal_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index, total_ips=len(ips))
            if not self.ibm_var_ip.get():
                csv_data = [col for i, col in enumerate(csv_data) if i not in (3, 10)]
            bad = "Possui má reputação" in terminal_output
            return (index, csv_data, terminal_output, ip, bad)
        results_buffer = []
        with ThreadPoolExecutor(max_workers=min(len(ips), 10)) as executor:
            futures = {executor.submit(process_ip, i + 1, ip): i for i, ip in enumerate(ips)}
            for future in as_completed(futures):
                if self.stop_flag:
                    break
                try:
                    result = future.result()
                    if result:
                        results_buffer.append(result)
                        results_buffer.sort(key=lambda x: x[0])
                        self.root.after(0, lambda: self.refresh_ip_output(results_buffer.copy()))
                except Exception as e:
                    self.root.after(0, lambda e=e: self.output_area.insert(tk.END, f"Erro ao processar IP: {e}\n"))
        if not self.stop_flag:
            self.root.after(0, lambda: messagebox.showinfo("Concluído", "Consulta finalizada."))
            
    def refresh_ip_output(self, sorted_results):
        self.output_area.delete("1.0", tk.END)
        self.results.clear()
        for index, csv_data, terminal_output, ip, bad in sorted_results:
            if bad:
                self.bad_ips.add(ip)
            self.results.append(csv_data)
            self.output_area.insert(tk.END, terminal_output + "\n")
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
                texto = (f"IP(s) com má reputação: {lista}\n"
                         f"Um chamado foi aberto com o MSS para efetuar o bloqueio do(s) IP(s): ")
            else:
                texto = (f"IP(s) com má reputação: {lista}\n"
                         f"Recomendamos o bloqueio do IP no firewall devido ao seu histórico de má reputação.")
        else:
            texto = "Nenhum indício de reputação maliciosa foi encontrado para o(s) IP(s) consultados."
        self.output_area.insert("1.0", texto + "\n")
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
                        ibm_score = "Desconhecido"
                finally:
                    self.driver_pool.put(driver)
            terminal_output = format_terminal_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, assoc_domain, index=1, total_ips=1)

            is_bad = "Possui má reputação" in terminal_output
            return terminal_output, is_bad
        except Exception as e:
            return f"Erro ao consultar IP associado {ip}: {e}", False

    # ---------- helpers de resolução de domínio p/ IP -------------
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
            for driver in drivers_to_close:
                try:
                    driver.quit()
                except Exception:
                    pass
        except Exception as e:
            print(f"Erro ao fechar drivers: {e}")
        finally:
            self.root.destroy()

import webbrowser
from tkinter import Toplevel, Label, Button

def show_update_window(latest_version, novidades_texto):
    update_win = Toplevel()
    update_win.title("Atualização disponível")
    update_win.configure(bg="#1e1e1e")
    update_win.geometry("500x300")
    Label(update_win, text=f"Uma nova versão do IP Shark está disponível: {latest_version}",
          bg="#1e1e1e", fg="white", font=("Segoe UI", 10, "bold")).pack(pady=(10, 5))
    Label(update_win, text="Novidades:", bg="#1e1e1e", fg="white", anchor="w",
          font=("Segoe UI", 10, "underline")).pack(pady=(5, 0), anchor="w", padx=10)
    novidades_lines = novidades_texto.strip().splitlines() if novidades_texto else ["• Não foi possível carregar as novidades."]
    for item in novidades_lines:
        Label(update_win, text="• " + item.strip(), bg="#1e1e1e", fg="white", anchor="w",
              font=("Segoe UI", 10)).pack(anchor="w", padx=20)
    def open_github():
        webbrowser.open("https://github.com/alexsilva-sh/IP-Shark/releases")
    link_label = Label(update_win, text="🔗 Clique aqui para baixar no GitHub",
                       fg="#00aaff", bg="#1e1e1e", cursor="hand2", font=("Segoe UI", 10, "bold"))
    link_label.pack(pady=20)
    link_label.bind("<Button-1>", lambda e: open_github())

if __name__ == "__main__":
    root = tk.Tk()
    root.title(f"IP Shark {__version__} - by @alexsilva.sh in Github")
    import os
    icon_path = os.path.join(os.path.dirname(__file__), '..', 'assets', 'shark.ico')
    icon_path = os.path.abspath(icon_path)
    if os.path.exists(icon_path):
        root.iconbitmap(icon_path)
    else:
        print(f"[AVISO] Ícone não encontrado em: {icon_path}")

    latest, novidades = check_latest_version()
    if latest:
        show_update_window(latest, novidades)
    app = IPCheckerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
