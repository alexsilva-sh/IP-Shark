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
from country_codes import COUNTRY_NAMES_LOCAL
from openpyxl import Workbook
from openpyxl import Workbook
from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
from openpyxl.utils import get_column_letter

if getattr(sys, 'frozen', False):
    BASE_DIR = os.path.dirname(sys.executable)
    BUNDLE_DIR = sys._MEIPASS
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
    BUNDLE_DIR = BASE_DIR

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

_last_dotenv_mtime = 0

def reload_api_keys():
    global ABUSEIPDB_API_KEY, VIRUSTOTAL_API_KEY, IPINFO_API_KEY, _last_dotenv_mtime
    if dotenv_path and os.path.exists(dotenv_path):
        try:
            current_mtime = os.path.getmtime(dotenv_path)
            if current_mtime != _last_dotenv_mtime:
                _last_dotenv_mtime = current_mtime
                load_dotenv(dotenv_path, override=True)
                print("[INFO] APIs recarregadas do arquivo api.env")
        except Exception:
            pass
    ABUSEIPDB_API_KEY = os.getenv('ABUSEIPDB_API_KEY')
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
    IPINFO_API_KEY = os.getenv('IPINFO_API_KEY')

ABUSEIPDB_API_KEY = None
VIRUSTOTAL_API_KEY = None
IPINFO_API_KEY = None
reload_api_keys()

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
    reload_api_keys()
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
    reload_api_keys()
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
        import time
        time.sleep(8)
        soup = BeautifulSoup(driver.page_source, "html.parser")
        h1 = soup.find("h1", class_="risklevelbar")
        if h1:
            score_span = h1.find("span", class_="numtitle")
            if score_span:
                try:
                    risk_score = float(score_span.text.strip())
                except ValueError:
                    risk_score = "unknown"
            else:
                risk_class = h1.get("class", [])
                if "high" in risk_class:
                    risk_score = "high"
                elif "medium" in risk_class:
                    risk_score = "medium"
                elif "low" in risk_class:
                    risk_score = "low"
                else:
                    risk_score = "unknown"
        else:
            risk_score = "unknown"
    except Exception:
        risk_score = "error"
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
            score = "high"
        elif "medium" in risk_class:
            score = "medium"
        elif "low" in risk_class:
            score = "low"
        else:
            score = "unknown"
    except Exception:
        score = "error"
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
    reload_api_keys()
    url = f"https://www.virustotal.com/api/v3/files/{hash_str}"
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException:
        return None

def check_hash_alienvault(hash_str):
    reload_api_keys()
    try:
        api_key = os.getenv("ALIENVAULT_API_KEY")
        link = f"https://otx.alienvault.com/indicator/file/{hash_str}"

        if not api_key:
            return "error_api_not_found", link
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
    reload_api_keys()
    try:
        api_key = os.getenv("ALIENVAULT_API_KEY")
        link = f"https://otx.alienvault.com/indicator/url/{url}"
        if not api_key:
            return "error_api_not_found", link
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
        risk_score = elem.text.strip() if elem else "unknown"
    except Exception:
        risk_score = "error"
    return risk_score

def check_url_virustotal(url):
    reload_api_keys()
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"score": "error_api_key_missing", "not_found": False}
    vt_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{vt_id}"
    headers = {"x-apikey": api_key, "Accept": "application/json"}
    try:
        resp = requests.get(api_url, headers=headers, timeout=15)
        if resp.status_code == 404:
            return {"score": "not_found", "not_found": True}
        resp.raise_for_status()
        data = resp.json()
        score = safe_get(data, "data", "attributes",
                         "last_analysis_stats", "malicious", default=0)
        return {"score": score, "not_found": False}
    except requests.exceptions.RequestException as e:
        return {"score": "error_request", "not_found": False}
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
    reload_api_keys()
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
        return abuseipdb_result['data'].get('isWhitelisted', False)
    except KeyError:
        return False

def translate_country_name(country_code):
    """
    Traduz código ISO de país para nome completo
    usando dicionário local.
    """
    if not country_code or country_code == 'N/A':
        return 'N/A'

    lang = os.getenv("APP_LANG", "pt")
    code = country_code.strip().upper()

    local_dict = COUNTRY_NAMES_LOCAL.get(lang, COUNTRY_NAMES_LOCAL.get("en", {}))
    return local_dict.get(code, country_code)

def _format_worksheet(ws):
    header_font = Font(name="Segoe UI", bold=True, color="FFFFFF", size=11)
    header_fill = PatternFill(start_color="007ACC", end_color="007ACC", fill_type="solid")
    header_alignment = Alignment(horizontal="center", vertical="center", wrap_text=True)
    cell_font = Font(name="Consolas", size=10)
    cell_alignment = Alignment(horizontal="center", vertical="center", wrap_text=False)
    thin_border = Border(
        left=Side(style="thin", color="CCCCCC"),
        right=Side(style="thin", color="CCCCCC"),
        top=Side(style="thin", color="CCCCCC"),
        bottom=Side(style="thin", color="CCCCCC")
    )
    row_fill_even = PatternFill(start_color="F2F2F2", end_color="F2F2F2", fill_type="solid")
    row_fill_odd = PatternFill(start_color="FFFFFF", end_color="FFFFFF", fill_type="solid")
    for cell in ws[1]:
        cell.font = header_font
        cell.fill = header_fill
        cell.alignment = header_alignment
        cell.border = thin_border
    for row_idx, row in enumerate(ws.iter_rows(min_row=2, max_row=ws.max_row, max_col=ws.max_column), start=2):
        fill = row_fill_even if row_idx % 2 == 0 else row_fill_odd
        for cell in row:
            cell.font = cell_font
            cell.alignment = cell_alignment
            cell.border = thin_border
            cell.fill = fill
    for col_idx in range(1, ws.max_column + 1):
        max_length = 0
        col_letter = get_column_letter(col_idx)
        for row in ws.iter_rows(min_row=1, max_row=ws.max_row, min_col=col_idx, max_col=col_idx):
            for cell in row:
                if cell.value:
                    max_length = max(max_length, len(str(cell.value)))
        adjusted_width = min(max_length + 4, 60)
        ws.column_dimensions[col_letter].width = adjusted_width
    ws.auto_filter.ref = ws.dimensions
    ws.freeze_panes = "A2"

def escolher_diretorio():
    root = tk.Tk()
    root.withdraw()
    diretorio = filedialog.askdirectory(title="Escolha onde salvar o arquivo CSV")
    return diretorio if diretorio else os.getcwd()

def save_to_csv(results, headers, filename="results.xlsx"):
    diretorio = escolher_diretorio()
    if filename.endswith(".csv"):
        filename = filename.replace(".csv", ".xlsx")
    filepath = os.path.join(diretorio, filename)
    wb = Workbook()
    ws = wb.active
    ws.title = "Resultados"
    ws.append(headers)
    for row in results:
        ws.append([str(v) if v is not None else "" for v in row])
    _format_worksheet(ws)
    wb.save(filepath)

def save_to_excel(domain_results, domain_headers, ip_results_by_domain, ip_headers, filename="domain_results.xlsx"):
    diretorio = escolher_diretorio()
    filepath = os.path.join(diretorio, filename)
    wb = Workbook()
    ws_domains = wb.active
    ws_domains.title = "Dominios"
    ws_domains.append(domain_headers)
    for row in domain_results:
        ws_domains.append([str(v) if v is not None else "" for v in row])
    _format_worksheet(ws_domains)
    for domain, ip_rows in ip_results_by_domain.items():
        safe_name = domain[:25]
        for char in ['/', '\\', '*', '?', ':', '[', ']']:
            safe_name = safe_name.replace(char, '_')
        ws_ip = wb.create_sheet(title=f"IPs - {safe_name}")
        ws_ip.append(ip_headers)
        for row in ip_rows:
            ws_ip.append([str(v) if v is not None else "" for v in row])
        _format_worksheet(ws_ip)
    wb.save(filepath)

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
        
def build_ip_result(ip, abuseipdb_result, virustotal_result, ibm_score,
                    city, country, domain):
    abuse_confidence = safe_get(abuseipdb_result, 'data', 'abuseConfidenceScore', default=0)
    vt_score = safe_get(virustotal_result, 'data', 'attributes',
                        'last_analysis_stats', 'malicious', default=0)
    whitelisted = is_whitelisted_abuseipdb(abuseipdb_result)

    try:
        ibm_numeric = float(ibm_score)
    except (ValueError, TypeError):
        ibm_numeric = 0

    has_bad_reputation = abuse_confidence > 0 or vt_score > 0 or ibm_numeric > 1

    last_reported_at = safe_get(abuseipdb_result, 'data', 'lastReportedAt')
    if last_reported_at:
        utc_time = datetime.fromisoformat(last_reported_at.replace('Z', '+00:00'))
        last_reported_at = (utc_time - timedelta(hours=3)).strftime('%Y-%m-%d %H:%M:%S')
    else:
        last_reported_at = None

    return {
        "ip": ip,
        "abuse_score": abuse_confidence,
        "vt_score": vt_score,
        "ibm_score": ibm_score,
        "status": (
            "whitelisted" if whitelisted else
            "bad" if has_bad_reputation else
            "clean"
        ),
        "domain": domain,
        "country": country,
        "city": city,
        "last_report": last_reported_at,
        "links": {
            "abuse": f"https://www.abuseipdb.com/check/{ip}",
            "vt": f"https://www.virustotal.com/gui/ip-address/{ip}",
            "ibm": f"https://exchange.xforce.ibmcloud.com/ip/{ip}" if ibm_score else None
        }
    }