import requests
import pyperclip
import ipaddress
import csv
import os
import sys
import tkinter as tk
from tkinter import filedialog
import unicodedata
import subprocess
from datetime import datetime, timedelta
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from bs4 import BeautifulSoup
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv
from selenium.webdriver.chrome.service import Service as ChromeService

if getattr(sys, 'frozen', False):  # está compilado
    BASE_DIR = os.path.dirname(sys.executable)
else:  # modo normal (script .py)
    BASE_DIR = os.path.dirname(__file__)

# Carrega o arquivo .env
dotenv_path = os.path.join(BASE_DIR, 'api.env')
load_dotenv(dotenv_path)

ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
IPINFO_API_KEY = os.getenv('IPINFO_API_KEY')

def safe_get(d, *keys, default=None):
    for key in keys:
        if isinstance(d, dict) and key in d:
            d = d[key]
        else:
            return default
    return d

def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def check_ip_abuseipdb(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': ABUSEIPDB_API_KEY}
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def check_ip_virustotal(ip):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

# novo
def check_ip_ibm(driver, ip):
    url = f"https://exchange.xforce.ibmcloud.com/ip/{ip}"
    driver.execute_script(f"window.open('{url}', '_blank');")
    driver.switch_to.window(driver.window_handles[-1])

    try:
        WebDriverWait(driver, 20).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "span.numtitle"))
        )
        soup = BeautifulSoup(driver.page_source, "html.parser")
        risk_element = soup.find("span", class_="scorebackgroundfilter numtitle")
        try:
            risk_score = float(risk_element.text.strip()) if risk_element else "Não encontrado"
        except ValueError:
            risk_score = "Não encontrado"
    except Exception:
        risk_score = "Erro na consulta"

    driver.close()
    driver.switch_to.window(driver.window_handles[0])
    return ip, risk_score


def start_browser():
    options = Options()
    options.add_argument("--headless=new")  # nova engine headless
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--log-level=3")

    # Resolve caminho do ChromeDriver e aplica flag correta
    chrome_path = ChromeDriverManager().install()
    service = ChromeService(executable_path=chrome_path)
    service.creationflags = subprocess.CREATE_NO_WINDOW  # Oculta janela do console no Windows

    driver = webdriver.Chrome(service=service, options=options)
    return driver
# novo

def get_location(ip):
    url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        city = data.get('city', 'N/A')
        country_code = data.get('country', 'N/A')
        country = translate_country_name(country_code)  #tradução

        return city, country
    except requests.exceptions.RequestException:
        return 'N/A', 'N/A'

def get_domain_from_abuseipdb(abuseipdb_result):
    try:
        return remover_acentos(abuseipdb_result['data'].get('domain', 'N/A')) if abuseipdb_result else 'N/A'
    except KeyError:
        return 'N/A'

def remover_acentos(texto):
    # Remove acentos e caracteres especiais de um texto 
    if isinstance(texto, str):
        return ''.join(c for c in unicodedata.normalize('NFD', texto) if unicodedata.category(c) != 'Mn')
    return texto

def is_whitelisted_abuseipdb(abuseipdb_result):
    try:
        return "Sim" if abuseipdb_result['data'].get('isWhitelisted', False) else "Não"
    except KeyError:
        return "Não"

COUNTRY_CACHE = {}
def translate_country_name(country_code):
    global COUNTRY_CACHE
    try:
        # Se o cache estiver vazio, buscar os dados da API
        if not COUNTRY_CACHE:
            response = requests.get("https://www.apicountries.com/countries")
            response.raise_for_status()
            countries = response.json()
            for country in countries:
                alpha2 = country.get("alpha2Code")
                name_pt = country.get("translations", {}).get("pt", country.get("name"))
                if alpha2:
                    COUNTRY_CACHE[alpha2.upper()] = name_pt

        # Buscar o nome traduzido no cache
        return COUNTRY_CACHE.get(country_code.upper(), country_code)

    except requests.exceptions.RequestException as e:
        print(f"Erro ao acessar API de países: {e}")
        return country_code

def escolher_diretorio():
    # Abre uma janela para o usuário escolher o diretório de salvamento
    root = tk.Tk()
    root.withdraw()
    diretorio = filedialog.askdirectory(title="Escolha onde salvar o arquivo CSV")
    return diretorio if diretorio else os.getcwd()  # Se não escolher, salva no diretório atual

def save_to_csv(results):
    diretorio = escolher_diretorio()
    filename = os.path.join(diretorio, "consulta_ips.csv")

    # Remove colunas do IBM se estiverem ausentes nos dados
    has_ibm = any(len(r) == 11 for r in results)

    headers = [
        "IP", "Score AbuseIPDB", "Score VirusTotal",
        *(["Score IBM"] if has_ibm else []),
        "Dominio", "Pais", "Cidade", "Ultima Denuncia",
        "AbuseIPDB Link", "VirusTotal Link",
        *(["IBM Link"] if has_ibm else [])
    ]

    with open(filename, mode="w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(results)

    print(f"\n***** Resultados salvos em: {filename} *****\n")

def format_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index):
    try:
        abuse_confidence = safe_get(abuseipdb_result, 'data', 'abuseConfidenceScore', default=0)
        vt_score = safe_get(virustotal_result, 'data', 'attributes', 'last_analysis_stats', 'malicious', default=0)
        #reputation_status = "Malicioso" if abuse_confidence > 0 or vt_score > 0 else "NÃO malicioso"

        abuseipdb_link = f"https://www.abuseipdb.com/check/{ip}"
        virustotal_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
        ibm_link = f"https://exchange.xforce.ibmcloud.com/ip/{ip}" if ibm_score is not None else ""

        last_reported_at = abuseipdb_result['data'].get('lastReportedAt') if abuseipdb_result else None
        if last_reported_at:
            utc_time = datetime.fromisoformat(last_reported_at.replace('Z', '+00:00'))
            brasilia_time = utc_time - timedelta(hours=3)
            last_reported_at_formatted = brasilia_time.strftime('%d/%m/%Y %H:%M:%S')
        else:
            last_reported_at_formatted = 'Nao possui denuncias'

        return [
            ip,
            f"{abuse_confidence}%",
            f"{vt_score}",
            f"{ibm_score}" if ibm_score is not None else "",
            domain,
            country,
            city,
            last_reported_at_formatted,
            abuseipdb_link,
            virustotal_link,
            ibm_link
        ]
    except Exception as e:
        return [f"Erro ao formatar a saída para {ip}: {e}", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A", "N/A"]

def format_terminal_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index):
    try:
        abuse_confidence = safe_get(abuseipdb_result, 'data', 'abuseConfidenceScore', default=0)
        vt_score = safe_get(virustotal_result, 'data', 'attributes', 'last_analysis_stats', 'malicious', default=0)
        whitelisted = is_whitelisted_abuseipdb(abuseipdb_result) == "Sim"

        abuseipdb_link = f"https://www.abuseipdb.com/check/{ip}"
        virustotal_link = f"https://www.virustotal.com/gui/ip-address/{ip}"
        
        try:
            ibm_numeric_score = float(ibm_score)
            ibm_score_valid = True
        except (ValueError, TypeError):
            ibm_numeric_score = 0
            ibm_score_valid = False
        ibm_link = f"https://exchange.xforce.ibmcloud.com/ip/{ip}" if ibm_score_valid else None
        
        has_bad_reputation = abuse_confidence > 0 or vt_score > 0 or ibm_numeric_score > 1

        if whitelisted:
            reputation_status = "NÃO possui má reputação (IP em Whitelist no AbuseIPDB)"
        else:
            reputation_status = "Possui má reputação" if has_bad_reputation else "NÃO possui má reputação"

        last_reported_at = safe_get(abuseipdb_result, 'data', 'lastReportedAt')
        if last_reported_at:
            utc_time = datetime.fromisoformat(last_reported_at.replace('Z', '+00:00'))
            brasilia_time = utc_time - timedelta(hours=3)
            last_reported_at_formatted = brasilia_time.strftime('%d/%m/%Y %H:%M:%S')
        else:
            last_reported_at_formatted = 'Não possui denúncias'

        output = f"""
[{index}] {ip} - {reputation_status}"""

        if not whitelisted:
            output += f"\nScore no AbuseIPDB: {abuse_confidence}%"
        else:
            output += f"\nScore no AbuseIPDB: {abuse_confidence}% (em Whitelist)"

        output += f"\nScore no VirusTotal: {vt_score}"

        if ibm_score_valid:
            output += f"\nScore no IBM X-Force: {ibm_score}"

        output += f"""
Nome de domínio: {domain}
País e cidade: {country}, {city}
Último relatório no AbuseIPDB: {last_reported_at_formatted}
- {abuseipdb_link}
- {virustotal_link}"""
        if ibm_link:
            output += f"\n- {ibm_link}"
    
        return output
    except Exception as e:
        return f"Erro ao formatar a saída para {ip}: {e}"

def main():
    print("""                                                                 
              ########                              
              ############                          
              ##############                        
              ################                                  
  _____ _____     _____ _                _    
 |_   _|  __  |  / ____| |              | |   
   | | | |__) | | (___ | |__   __ _ _ __| | __
   | | |  ___/   |___ || '_ | | _ | '__| |/ /
  _| |_| |       ____) | | | | (_| | |  |   /
 |_____|_|      |_____/|_| |_||__,_|_|  |_||_|
              #######################                
              ############################                       
              ################################          
              #####################################          
              ##########################################      
              ################################################
              # Desenvolvido por @alexsilva-sh #####################
              # Contribua https://github.com/alexsilva-sh/IP-Shark #####
    """)
    print("Iniciando Chrome em segundo plano...")
    driver = start_browser()
    print("Pronto para uso")
    print(" ")
    
    while True:
        ips_input = input("Digite os IPs para consulta (separados por vírgula) ou 'sair' para encerrar: ")
        if ips_input.lower() == 'sair':
            break

        ips = [ip.strip() for ip in ips_input.split(",") if ip.strip()]

        all_results = []
        all_outputs = ""

        for index, ip in enumerate(tqdm(
            ips,
            desc="Consultando IPs",
            ncols=100,
            bar_format="{l_bar}{bar} Tempo restante: {remaining}"
        ), 1):
            if not is_valid_ip(ip):
                print(f"IP inválido: {ip}.")
                continue

            # Execução paralela das APIs AbuseIPDB e VirusTotal
            with ThreadPoolExecutor(max_workers=2) as executor:
                future_abuse = executor.submit(check_ip_abuseipdb, ip)
                future_vt = executor.submit(check_ip_virustotal, ip)
                abuseipdb_result = future_abuse.result()
                virustotal_result = future_vt.result()

            city, country = get_location(ip)
            domain = get_domain_from_abuseipdb(abuseipdb_result)
            _, ibm_score = check_ip_ibm(driver, ip)

            csv_result = format_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index)
            all_results.append(csv_result)

            terminal_output = format_terminal_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index)
            all_outputs += terminal_output + "\n"

        if len(ips) >= 5:
            save_to_csv(all_results)
        else:
            print(all_outputs)
            pyperclip.copy(all_outputs)
            print("O resultado foi copiado para a área de transferência.")
            print("#######################################################################################################")
            print("#######################################################################################################")
            print(" ")
            print(" ")

    driver.quit()
    
if __name__ == "__main__":
    main()
