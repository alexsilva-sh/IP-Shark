import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
from tkinter import ttk
import pyperclip
from threading import Thread
import ipaddress

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
    save_to_csv
)

class IPCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("IP Shark - ISH Blue Team - @alexsilva.sh on Github")
        self.root.configure(bg="#1e1e1e")

        self.driver = start_browser()

        # Estilo
        label_font = ("Segoe UI", 10)
        entry_font = ("Consolas", 10)
        button_font = ("Segoe UI", 10, "bold")

        # Label
        self.input_label = tk.Label(root, text="Digite os IPs separados por vírgula:", bg="#1e1e1e", fg="white", font=label_font)
        self.input_label.pack(pady=(10, 2))

        # Entry
        self.entry = tk.Entry(root, width=90, bg="#2d2d2d", fg="white", insertbackground='white', font=entry_font, relief=tk.FLAT)
        self.entry.pack(pady=5, padx=10, ipady=4)

        # Checkbox IBM
        self.ibm_var = tk.BooleanVar(value=True)
        self.ibm_checkbox = tk.Checkbutton(root, text="Consultar com IBM X-Force", variable=self.ibm_var,
                                           bg="#1e1e1e", fg="white", activebackground="#1e1e1e", activeforeground="white",
                                           selectcolor="#1e1e1e", font=label_font)
        self.ibm_checkbox.pack(pady=2)

        # Botão
        self.check_button = tk.Button(root, text="🔍 Realizar consulta", command=self.run_check, bg="#007acc", fg="white", font=button_font, relief=tk.FLAT, activebackground="#005f99")
        self.check_button.pack(pady=10)

        # Barra de Progresso
        self.progress = ttk.Progressbar(root, orient="horizontal", length=600, mode="determinate")
        self.progress.pack(pady=(0, 10))
        self.progress["value"] = 0

        # Área de saída
        self.output_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=100, height=30, bg="#1e1e1e", fg="white", font=entry_font, insertbackground='white')
        self.output_area.pack(padx=10, pady=(0, 10))

        # Botões auxiliares
        self.button_frame = tk.Frame(root, bg="#1e1e1e")
        self.button_frame.pack(pady=(0, 10))

        self.copy_button = tk.Button(self.button_frame, text="Copiar Resultado", command=self.copy_output, bg="#333333", fg="white", font=label_font, relief=tk.FLAT)
        self.copy_button.grid(row=0, column=0, padx=10)

        self.save_button = tk.Button(self.button_frame, text="Exportar para CSV", command=self.save_results, bg="#333333", fg="white", font=label_font, relief=tk.FLAT)
        self.save_button.grid(row=0, column=1, padx=10)

        self.results = []

    def copy_output(self):
        pyperclip.copy(self.output_area.get("1.0", tk.END))

    def save_results(self):
        if self.results:
            save_to_csv(self.results)
        else:
            messagebox.showwarning("Aviso", "Nenhum resultado para salvar.")

    def run_check(self):
        self.output_area.delete("1.0", tk.END)  # limpa resultados anteriores

        raw_ips = self.entry.get()
        ips_raw_list = [ip.strip() for ip in raw_ips.split(",")]

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
        self.progress["maximum"] = len(ips)
        self.progress["value"] = 0

        Thread(target=self._check_ips_thread, args=(ips,), daemon=True).start()

    def _check_ips_thread(self, ips):
        for index, ip in enumerate(ips, 1):
            abuseipdb_result = check_ip_abuseipdb(ip)
            virustotal_result = check_ip_virustotal(ip)
            city, country = get_location(ip)
            domain = get_domain_from_abuseipdb(abuseipdb_result)
            ibm_score = None

            if self.ibm_var.get():
                _, ibm_score = check_ip_ibm(self.driver, ip)
            else:
                ibm_score = None

            csv_data = format_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index)
            terminal_output = format_terminal_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index)

            if not self.ibm_var.get():
                # Remove Score IBM (índice 3) e IBM Link (índice -1)
                csv_data = [col for i, col in enumerate(csv_data) if i not in (3, 10)]

            self.results.append(csv_data)
            self.output_area.insert(tk.END, terminal_output + "\n")
            self.output_area.see(tk.END)
            self.progress["value"] += 1

        messagebox.showinfo("Concluído", "Consulta finalizada.")

    def on_close(self):
        self.driver.quit()
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.title("IP Shark - ISH Blue Team - @alexsilva.sh on Github")
    root.iconbitmap("shark.ico")  # Adicione esta linha aqui
    app = IPCheckerApp(root)
    root.protocol("WM_DELETE_WINDOW", app.on_close)
    root.mainloop()
