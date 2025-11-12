import base64
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

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

possible_paths = [
    os.path.join(BASE_DIR, 'config', 'api.env'),
    os.path.join(BASE_DIR, '..', 'config', 'api.env')
]
dotenv_path = next((p for p in possible_paths if os.path.exists(p)), None)

if dotenv_path:
    load_dotenv(dotenv_path)
    print(f"[INFO] Variáveis de API carregadas de: {dotenv_path}")
else:
    print(f"[ERRO] Arquivo api.env não encontrado. Verifique se ele está em /config/api.env")

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

def check_ip_ibm(driver, ip):
    url = f"https://exchange.xforce.ibmcloud.com/ip/{ip}"
    driver.execute_script(f"window.open('{url}', '_blank');")
    driver.switch_to.window(driver.window_handles[-1])

    try:
        WebDriverWait(driver, 18).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "span.numtitle")))
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

def check_hash_ibm(driver, hash_str):
    url = f"https://exchange.xforce.ibmcloud.com/malware/{hash_str}"
    driver.execute_script(f"window.open('{url}', '_blank');")
    driver.switch_to.window(driver.window_handles[-1])

    try:
        WebDriverWait(driver, 18).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, ".risklevelbar")))
        soup = BeautifulSoup(driver.page_source, "html.parser")
        risk_element = soup.find(class_="risklevelbar")
        risk_class = risk_element.get("class", []) if risk_element else []
        if "high" in risk_class:
            score = "Alto"
        elif "medium" in risk_class:
            score = "Médio"
        elif "low" in risk_class:
            score = "Baixo"
        else:
            score = "Desconhecido"
    except Exception:
        score = "Erro na consulta"
    driver.close()
    driver.switch_to.window(driver.window_handles[0])
    return hash_str, score

def check_hash_joesandbox(driver, hash_str):
    base_url = "https://www.joesandbox.com/analysis/search?q="
    search_url = base_url + hash_str
    driver.execute_script(f"window.open('{search_url}', '_blank');")
    driver.switch_to.window(driver.window_handles[-1])
    found = False
    try:
        WebDriverWait(driver, 18).until(
            EC.presence_of_element_located((By.TAG_NAME, "body")))
        found = "Full Report" in driver.page_source
    except Exception:
        pass
    driver.close()
    driver.switch_to.window(driver.window_handles[0])
    return found, search_url

def check_hash_virustotal(hash_str):
    url = f"https://www.virustotal.com/api/v3/files/{hash_str}"
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def check_hash_alienvault(hash_str):
    try:
        api_key = os.getenv("ALIENVAULT_API_KEY")
        link = f"https://otx.alienvault.com/indicator/file/{hash_str}"

        if not api_key:
            return "Erro, api não localizada", link
        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"}

        url = f"https://otx.alienvault.com/api/v1/indicators/file/{hash_str}/general"
        response = requests.get(url, headers=headers, timeout=15)

        if response.status_code != 200:
            return "0", link

        data = response.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return str(pulse_count), link
    except Exception as e:
        return "0", f"https://otx.alienvault.com/indicator/file/{hash_str}"

def check_url_alienvault(url):
    try:
        api_key = os.getenv("ALIENVAULT_API_KEY")
        link = f"https://otx.alienvault.com/indicator/url/{url}"
        if not api_key:
            return "Erro, api não localizada", link
        headers = {
            "X-OTX-API-KEY": api_key,
            "Accept": "application/json"}
        url = f"https://otx.alienvault.com/api/v1/indicators/url/{url}/general"
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code != 200:
            return "0", link
        data = response.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        return str(pulse_count), link
    except Exception as e:
        return "0", f"https://otx.alienvault.com/indicator/url/{url}"

def check_url_ibm(driver, url):
    ibm_url = f"https://exchange.xforce.ibmcloud.com/url/{url}"
    if len(driver.window_handles) > 1:
        driver.close()
        driver.switch_to.window(driver.window_handles[0])
    driver.get(ibm_url)
    try:
        WebDriverWait(driver, 18).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "h2.scorebackgroundfilter.numtitle")))
        soup = BeautifulSoup(driver.page_source, "html.parser")
        elem = soup.find("h2", class_="scorebackgroundfilter numtitle")
        risk_score = elem.text.strip() if elem else "Não encontrado"
    except Exception:
        risk_score = "Erro na consulta"
    return risk_score

def check_url_virustotal(url):
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"score": "Erro: API KEY não definida", "not_found": False}
    vt_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        resp = requests.get(api_url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return {"score": "Não encontrado", "not_found": True}
        resp.raise_for_status()
        data = resp.json()
        score = safe_get(data, "data", "attributes",
                         "last_analysis_stats", "malicious", default=0)
        return {"score": score, "not_found": False}
    except requests.exceptions.RequestException as e:
        return {"score": f"Erro: {e}", "not_found": False}

def start_browser():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--log-level=3")
    chrome_path = ChromeDriverManager().install()
    service = ChromeService(executable_path=chrome_path)
    service.creationflags = subprocess.CREATE_NO_WINDOW
    driver = webdriver.Chrome(service=service, options=options)
    return driver

def get_location(ip):
    url = f"https://ipinfo.io/{ip}/json?token={IPINFO_API_KEY}"
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        city = data.get('city', 'N/A')
        country_code = data.get('country', 'N/A')
        country = translate_country_name(country_code)
        return city, country
    except requests.exceptions.RequestException:
        return 'N/A', 'N/A'

def get_domain_from_abuseipdb(abuseipdb_result):
    try:
        return remover_acentos(abuseipdb_result['data'].get('domain', 'N/A')) if abuseipdb_result else 'N/A'
    except KeyError:
        return 'N/A'

def remover_acentos(texto):
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
        if not COUNTRY_CACHE:
            response = requests.get("https://www.apicountries.com/countries")
            response.raise_for_status()
            countries = response.json()
            for country in countries:
                alpha2 = country.get("alpha2Code")
                name_pt = country.get("translations", {}).get("pt", country.get("name"))
                if alpha2:
                    COUNTRY_CACHE[alpha2.upper()] = name_pt
        return COUNTRY_CACHE.get(country_code.upper(), country_code)
    except requests.exceptions.RequestException as e:
        print(f"Erro ao acessar API de países: {e}")
        return country_code

def escolher_diretorio():
    root = tk.Tk()
    root.withdraw()
    diretorio = filedialog.askdirectory(title="Escolha onde salvar o arquivo CSV")
    return diretorio if diretorio else os.getcwd()

def save_to_csv(results):
    diretorio = escolher_diretorio()
    filename = os.path.join(diretorio, "ips_results.csv")
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

def format_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index):
    try:
        abuse_confidence = safe_get(abuseipdb_result, 'data', 'abuseConfidenceScore', default=0)
        vt_score = safe_get(virustotal_result, 'data', 'attributes', 'last_analysis_stats', 'malicious', default=0)
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

def format_terminal_output(ip, abuseipdb_result, virustotal_result, ibm_score, city, country, domain, index, total_ips=1):
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

        if total_ips == 1:
            output = f"\n[{ip}] - {reputation_status}"
        else:
            output = f"\n[{index}] {ip} - {reputation_status}"

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
