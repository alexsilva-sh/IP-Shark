"""Consultas que dependem de navegador: IBM X-Force e JoeSandbox."""
import re
import subprocess
import time
from collections import Counter
from datetime import datetime

from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.common.by import By
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.support.ui import WebDriverWait
from webdriver_manager.chrome import ChromeDriverManager

import log

# So o tipo da excecao vai para o registro: a mensagem do Selenium costuma trazer a URL
# consultada, e com ela o indicador do cliente.
_log = log.obter("navegador")

ESPERA_PAGINA = 18

# Freio de ritmo, nao espera de pagina -- disso o WebDriverWait ja cuida. O tamanho=3 do
# DriverPool foi calibrado para nao disparar o bloqueio do X-Force quando cada consulta
# prendia o driver por 8 s; medir a taxa de bloqueio antes de baixar este piso.
PISO_XFORCE_IP = 2.0

JOE_BASE = "https://www.joesandbox.com"

# Do pior para o melhor: decide qual analise manda quando a busca devolve varias.
JOE_VEREDITOS = ("malicious", "suspicious", "clean")

JOE_FLAGS_ORDEM = (
    "has_malwareconfig", "injects", "drops_pe", "creates_files", "writes_registry_keys",
    "has_http", "has_traffic", "more_processes", "email_headers", "native_cmd",
    "sends_sms", "recv_sms", "reboot", "has_expired",
)
# Descrevem recursos do laudo no site, nao a amostra.
JOE_FLAGS_IGNORADAS = frozenset({"has_dis", "vnc_interactive"})


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
    """Placar do X-Force para um IP.

    Leitura que falha devolve "error", nunca "unknown": "unknown" vira FONTE_SEM_DADOS,
    que nao entra em fontes_indisponiveis e deixaria a pagina lenta sair como IP limpo.
    """
    inicio = time.monotonic()
    _abrir_aba(driver, f"https://exchange.xforce.ibmcloud.com/ip/{ip}")
    try:
        WebDriverWait(driver, ESPERA_PAGINA).until(
            EC.presence_of_element_located((By.CSS_SELECTOR, "h1.risklevelbar")))
        soup = BeautifulSoup(driver.page_source, "html.parser")
        h1 = soup.find("h1", class_="risklevelbar")
        score_span = h1.find("span", class_="numtitle") if h1 else None
        if score_span:
            risk_score = float(score_span.text.strip())
        else:
            risk_class = h1.get("class", []) if h1 else []
            if "high" in risk_class:
                risk_score = "high"
            elif "medium" in risk_class:
                risk_score = "medium"
            elif "low" in risk_class:
                risk_score = "low"
            else:
                risk_score = "error"
    except Exception as e:
        _log.warning("X-Force de IP nao rendeu placar legivel: %s", type(e).__name__)
        risk_score = "error"
    restante = PISO_XFORCE_IP - (time.monotonic() - inicio)
    if restante > 0:
        time.sleep(restante)
    _fechar_aba(driver)
    return ip, risk_score


def check_hash_ibm(driver, hash_str):
    _abrir_aba(driver, f"https://exchange.xforce.ibmcloud.com/malware/{hash_str}")
    try:
        WebDriverWait(driver, ESPERA_PAGINA).until(
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
    except Exception as e:
        _log.warning("X-Force de hash nao rendeu placar legivel: %s", type(e).__name__)
        score = "error"
    _fechar_aba(driver)
    return hash_str, score


def check_url_ibm(driver, url):
    ibm_url = f"https://exchange.xforce.ibmcloud.com/url/{url}"
    if len(driver.window_handles) > 1:
        _fechar_aba(driver)
    driver.get(ibm_url)
    try:
        WebDriverWait(driver, ESPERA_PAGINA).until(
            EC.presence_of_element_located(
                (By.CSS_SELECTOR, "h2.scorebackgroundfilter.numtitle")))
        soup = BeautifulSoup(driver.page_source, "html.parser")
        elem = soup.find("h2", class_="scorebackgroundfilter numtitle")
        return elem.text.strip() if elem else "unknown"
    except Exception as e:
        _log.warning("X-Force de dominio nao rendeu placar legivel: %s", type(e).__name__)
        return "error"


def _joe_icones(linha, sufixo):
    """{codigo: rotulo} dos icones de uma <tr>, pelo sufixo da classe do <span>."""
    achados = {}
    for icone in linha.select(f"td.class-info .{sufixo}"):
        for codigo in icone.get("class", []):
            if codigo != sufixo and codigo not in JOE_FLAGS_IGNORADAS:
                achados[codigo] = (icone.get("title") or codigo).strip()
    return achados


def _joe_instante(bruto):
    """'2021-02-08 20:58:09 +01:00' virado datetime."""
    try:
        return datetime.strptime((bruto or "").strip(), "%Y-%m-%d %H:%M:%S %z")
    except ValueError:
        return None


def _joe_analise(linha):
    deteccao = linha.find("td", class_="detection")
    classes = deteccao.get("class", []) if deteccao else []
    nome = linha.select_one("div.file-name span.clipper")
    data = linha.select_one("div.file-date")
    arquitetura = linha.select_one("div.architecture")
    av = linha.find("div", class_="av-detection")
    numero = re.search(r"\d+", av.get_text()) if av else None

    links = {}
    for ancora in linha.select("a.open-report[href]"):
        href = ancora["href"]
        if href.endswith("/iochtml"):
            links["ioc"] = JOE_BASE + href
        elif href.endswith("/html"):
            links["html"] = JOE_BASE + href

    return {
        "veredito": next((v for v in JOE_VEREDITOS if v in classes), None),
        "av": int(numero.group()) if numero else None,
        "flags": _joe_icones(linha, "infos-small"),
        "classes": _joe_icones(linha, "classifications-small"),
        "arquivo": (nome.get("title") or nome.get_text(strip=True)) if nome else None,
        "plataforma": (arquitetura.get("title") or "").split(":")[-1].strip()
                      if arquitetura else None,
        "instante": _joe_instante(data.get("title")) if data else None,
        "link_html": links.get("html"),
        "link_ioc": links.get("ioc"),
    }


def parse_busca_joesandbox(html):
    """Resumo das analises da busca, ou None quando nao ha nenhuma.

    Sem linha na tabela nao existe dict: o JoeSandbox so entra no relatorio quando tem algo
    a dizer sobre a amostra.
    """
    soup = BeautifulSoup(html, "html.parser")
    # A legenda no pe da pagina repete a classe e o title de todos os icones possiveis; ler
    # icone fora da <tr> faria toda amostra sair com todas as flags.
    analises = [_joe_analise(linha)
                for linha in soup.select("table#all_analyses_list tr.analysis")]
    if not analises:
        return None

    contagem = Counter(a["veredito"] for a in analises if a["veredito"])
    pior = next((v for v in JOE_VEREDITOS if v in contagem), None)
    # Juntar o comportamento das analises que nao sustentam o veredito atribuiria a amostra
    # o que uma execucao limpa fez.
    decisivas = [a for a in analises if a["veredito"] == pior] or analises
    decisivas.sort(reverse=True, key=lambda a: a["instante"].timestamp()
                   if a["instante"] else float("-inf"))
    principal = decisivas[0]

    flags, classes = {}, {}
    for analise in decisivas:
        flags.update(analise["flags"])
        classes.update(analise["classes"])
    ordem = {codigo: i for i, codigo in enumerate(JOE_FLAGS_ORDEM)}

    return {
        "veredito": pior,
        "av": principal["av"],
        "flags": {c: flags[c] for c in sorted(flags, key=lambda c: ordem.get(c, len(ordem)))},
        "classes": classes,
        "arquivo": principal["arquivo"],
        "plataforma": principal["plataforma"],
        "data": principal["instante"].strftime("%d/%m/%Y %H:%M:%S")
                if principal["instante"] else None,
        "analises": len(analises),
        "decisivas": contagem.get(pior, 0),
        "link_html": principal["link_html"],
        "link_ioc": principal["link_ioc"],
    }


def check_hash_joesandbox(driver, hash_str):
    """Resumo do JoeSandbox para o hash, ou None quando a busca nao achou analise."""
    search_url = f"https://www.joesandbox.com/analysis/search?q={hash_str}"
    _abrir_aba(driver, search_url)
    joe = None
    try:
        WebDriverWait(driver, ESPERA_PAGINA).until(
            EC.presence_of_element_located((By.TAG_NAME, "body")))
        joe = parse_busca_joesandbox(driver.page_source)
    except Exception as e:
        # Falha vira "sem analise" sem repetir o defeito do item 15: o JoeSandbox so agrava
        # veredito, entao nao produz um "limpo" que as outras fontes ja nao produziriam.
        _log.warning("JoeSandbox nao rendeu resultado legivel; assumido 'sem analise': %s",
                     type(e).__name__)
    _fechar_aba(driver)
    return joe, search_url
