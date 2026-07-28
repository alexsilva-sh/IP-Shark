"""Consultas que dependem de navegador: IBM X-Force e JoeSandbox."""
import subprocess

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager


def start_browser():
    options = Options()
    options.add_argument("--headless=new")
    options.add_argument("--disable-gpu")
    options.add_argument("--window-size=1920,1080")
    options.add_argument("--log-level=3")
    service = ChromeService(executable_path=ChromeDriverManager().install())
    service.creationflags = subprocess.CREATE_NO_WINDOW
    return webdriver.Chrome(service=service, options=options)


def _abrir_aba(driver, url):
    driver.execute_script("window.open(arguments[0], '_blank');", url)
    driver.switch_to.window(driver.window_handles[-1])


def _fechar_aba(driver):
    driver.close()
    driver.switch_to.window(driver.window_handles[0])


def check_ip_ibm(driver, ip):
    _abrir_aba(driver, f"https://exchange.xforce.ibmcloud.com/ip/{ip}")
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
    _fechar_aba(driver)
    return ip, risk_score


def check_hash_ibm(driver, hash_str):
    _abrir_aba(driver, f"https://exchange.xforce.ibmcloud.com/malware/{hash_str}")
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
    _fechar_aba(driver)
    return hash_str, score


def check_url_ibm(driver, url):
    ibm_url = f"https://exchange.xforce.ibmcloud.com/url/{url}"
    if len(driver.window_handles) > 1:
        _fechar_aba(driver)
    driver.get(ibm_url)
    try:
        WebDriverWait(driver, 18).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "h2.scorebackgroundfilter.numtitle")))
        soup = BeautifulSoup(driver.page_source, "html.parser")
        elem = soup.find("h2", class_="scorebackgroundfilter numtitle")
        return elem.text.strip() if elem else "unknown"
    except Exception:
        return "error"


def check_hash_joesandbox(driver, hash_str):
    search_url = f"https://www.joesandbox.com/analysis/search?q={hash_str}"
    _abrir_aba(driver, search_url)
    found = False
    try:
        WebDriverWait(driver, 18).until(
            EC.presence_of_element_located((By.TAG_NAME, "body")))
        found = "Full Report" in driver.page_source
    except Exception:
        pass
    _fechar_aba(driver)
    return found, search_url
