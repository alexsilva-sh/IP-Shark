"""Consultas que dependem de navegador: hoje so o JoeSandbox.

O IBM X-Force saiu daqui quando a IBM fechou o portal atras de login: a sessao do site nao
pode ser reaproveitada, e o que restou foi a API, em `core/api.py`.
"""
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
