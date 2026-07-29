"""Estado por fonte: indisponibilidade nunca pode virar 'limpo'.

Todo HTTP e mockado -- nenhuma requisicao real sai daqui.
"""
import threading
import time
import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace

from _comum import check, encerrar

import requests
from selenium.common.exceptions import NoSuchElementException
from core import api as core
import app as gui
from core import navegador, reputacao
from i18n import t
from ui import apresentacao, tema

gui.IPCheckerApp._init_drivers_async = lambda self, count=3: None

chamadas = []
_sessao_real = core._sessao   # guardado antes de mockar(), que substitui a fabrica


class RespostaFake:
    def __init__(self, status, payload=None, quebrado=False, headers=None):
        self.status_code = status
        self._payload = payload or {}
        self._quebrado = quebrado
        self.headers = headers or {}

    def json(self):
        if self._quebrado:
            raise ValueError("json invalido")
        return self._payload


def mockar(resposta):
    """Troca o GET da Session por algo que devolve `resposta` (ou levanta, se for excecao)."""
    def _fake(url, **kwargs):
        chamadas.append(kwargs)
        if isinstance(resposta, Exception):
            raise resposta
        return resposta
    core._sessao = lambda: SimpleNamespace(get=_fake)


core.ABUSEIPDB_API_KEY = "k"
core.VIRUSTOTAL_API_KEY = "k"
core.ALIENVAULT_API_KEY = "k"
core.reload_api_keys = lambda forcar=False: None

print("\n[1] Classificacao das respostas HTTP")
casos = [
    (RespostaFake(200, {"a": 1}), core.FONTE_OK, "200 com json -> ok"),
    (RespostaFake(404), core.FONTE_SEM_DADOS, "404 -> sem dados"),
    (RespostaFake(429), core.FONTE_COTA, "429 -> cota"),
    (RespostaFake(401), core.FONTE_SEM_CHAVE, "401 -> sem chave"),
    (RespostaFake(403), core.FONTE_SEM_CHAVE, "403 -> sem chave"),
    (RespostaFake(500), core.FONTE_INDISPONIVEL, "500 -> indisponivel"),
    (RespostaFake(200, quebrado=True), core.FONTE_INDISPONIVEL, "json ilegivel -> indisponivel"),
    (requests.exceptions.Timeout(), core.FONTE_INDISPONIVEL, "timeout -> indisponivel"),
    (requests.exceptions.ConnectionError(), core.FONTE_INDISPONIVEL, "sem rede -> indisponivel"),
]
for resposta, esperado, msg in casos:
    mockar(resposta)
    _dados, estado = core._consultar("https://exemplo")
    check(estado == esperado, f"{msg} (veio {estado})")

print("\n[2] Toda consulta HTTP leva timeout")
check(all("timeout" in kw for kw in chamadas), "todas as chamadas passaram timeout")
check(all(kw["timeout"] == core.TIMEOUT_HTTP for kw in chamadas), "timeout e o padrao do modulo")

print("\n[2b] Sessao reaproveitada e recuo configurado, sem retentar cota")
sessao = _sessao_real()
check(sessao is _sessao_real(), "a mesma thread reaproveita a Session (keep-alive)")
de_outra_thread = []
aux = threading.Thread(target=lambda: de_outra_thread.append(_sessao_real()))
aux.start()
aux.join()
check(de_outra_thread[0] is not sessao,
      "cada thread tem a sua -- Session do requests nao e thread-safe")
recuo = sessao.get_adapter("https://exemplo").max_retries
check(recuo.total == 2 and recuo.backoff_factor > 0,
      f"recuo exponencial configurado (total={recuo.total}, fator={recuo.backoff_factor})")
check(429 not in recuo.status_forcelist,
      "429 fora do forcelist: cota nao se resolve retentando, e o Retry-After congelaria a varredura")
check(set(recuo.status_forcelist) >= {500, 502, 503, 504}, "erro transitorio de servidor retenta")

print("\n[2c] Retry-After do 429 e lido para o aviso de cota")
mockar(RespostaFake(429, headers={"Retry-After": "1800"}))
_r, estado = core.check_ip_abuseipdb("8.8.8.8")
check(estado == core.FONTE_COTA, "429 continua virando cota na hora, sem dormir")
check(core.espera_de_cota("AbuseIPDB") == 1800, "espera registrada para a fonte certa")
check(core.espera_de_cota("VirusTotal") is None, "fonte que nao estourou nao ganha espera")
mockar(RespostaFake(429, headers={"Retry-After": "Wed, 21 Oct 2026 07:28:00 GMT"}))
_score, _link, _estado = core.check_hash_alienvault("a" * 32)
check(core.espera_de_cota("AlienVault") is None,
      "Retry-After em data nao vira estimativa inventada")
aviso = apresentacao.aviso_de_cota({"AbuseIPDB"})
check("30 min" in aviso, f"o aviso de cota diz em quanto tempo repetir ({aviso[-32:]!r})")
check(apresentacao.aviso_de_cota({"VirusTotal"}) == t("quota_warning").format(fontes="VirusTotal"),
      "fonte sem Retry-After mantem o aviso de antes, sem estimativa inventada")

print("\n[3] Fonte sem chave nem chega a fazer request")
core.ABUSEIPDB_API_KEY = None
mockar(RespostaFake(200, {"data": {}}))
antes = len(chamadas)
_r, estado = core.check_ip_abuseipdb("8.8.8.8")
check(estado == core.FONTE_SEM_CHAVE, "sem chave -> FONTE_SEM_CHAVE")
check(len(chamadas) == antes, "nao gastou requisicao")
core.ABUSEIPDB_API_KEY = "k"

print("\n[4] O BUG CRITICO: falha de API nao pode virar 'limpo'")
ABUSE_LIMPO = {"data": {"abuseConfidenceScore": 0, "isWhitelisted": False}}
VT_LIMPO = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}
VT_RUIM = {"data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}}

tudo_ok = reputacao.build_ip_result("1.1.1.1", ABUSE_LIMPO, VT_LIMPO, None, "c", "p", "d",
                               estado_abuse=core.FONTE_OK, estado_vt=core.FONTE_OK,
                               estado_ibm=None)
check(tudo_ok["status"] == "clean", "todas as fontes responderam e nada achado -> clean")

abuse_fora = reputacao.build_ip_result("1.1.1.1", None, VT_LIMPO, None, "c", "p", "d",
                                  estado_abuse=core.FONTE_INDISPONIVEL,
                                  estado_vt=core.FONTE_OK, estado_ibm=None)
check(abuse_fora["status"] == "incompleto", "AbuseIPDB fora do ar -> incompleto, NAO clean")
check(abuse_fora["abuse_score"] is None, "score da fonte ausente e None, nunca 0")
check(abuse_fora["fontes_indisponiveis"] == ["AbuseIPDB"], "aponta qual fonte faltou")

cota = reputacao.build_ip_result("1.1.1.1", None, VT_LIMPO, None, "c", "p", "d",
                            estado_abuse=core.FONTE_COTA, estado_vt=core.FONTE_OK,
                            estado_ibm=None)
check(cota["status"] == "incompleto", "cota estourada -> incompleto")
check(cota["cota_estourada"] is True, "sinaliza cota estourada")

sem_chave = reputacao.build_ip_result("1.1.1.1", None, None, None, "c", "p", "d",
                                 estado_abuse=core.FONTE_SEM_CHAVE,
                                 estado_vt=core.FONTE_SEM_CHAVE, estado_ibm=None)
check(sem_chave["status"] == "incompleto", "sem chave -> incompleto")

print("\n[5] Deteccao de fonte que respondeu continua valendo")
uma_fora = reputacao.build_ip_result("1.1.1.1", None, VT_RUIM, None, "c", "p", "d",
                                estado_abuse=core.FONTE_INDISPONIVEL,
                                estado_vt=core.FONTE_OK, estado_ibm=None)
check(uma_fora["status"] == "bad", "VT detectou com AbuseIPDB fora -> bad (conclusao valida)")

wl = {"data": {"abuseConfidenceScore": 0, "isWhitelisted": True}}
check(reputacao.build_ip_result("1.1.1.1", wl, VT_RUIM, None, "c", "p", "d")["status"] == "whitelisted_bad",
      "whitelist + deteccao -> whitelisted_bad")
check(reputacao.build_ip_result("1.1.1.1", wl, VT_LIMPO, None, "c", "p", "d")["status"] == "whitelisted",
      "whitelist com tudo respondendo -> whitelisted")

print("\n[6] IBM: 'error' e indisponivel, 'unknown' e sem dados")
check(reputacao.classificar_ibm("error") == core.FONTE_INDISPONIVEL, "error -> indisponivel")
check(reputacao.classificar_ibm("unknown") == core.FONTE_SEM_DADOS, "unknown -> sem dados")
check(reputacao.classificar_ibm("1.0") == core.FONTE_OK, "score -> ok")
check(reputacao.classificar_ibm(None) is None, "None -> fonte nao consultada")
ibm_fora = reputacao.build_ip_result("1.1.1.1", ABUSE_LIMPO, VT_LIMPO, "error", "c", "p", "d",
                                estado_ibm=core.FONTE_INDISPONIVEL)
check(ibm_fora["status"] == "incompleto", "X-Force fora do ar -> incompleto")

print("\n[6b] Hash e dominio seguem a mesma regra, no mesmo lugar")
VT_HASH_LIMPO = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0},
                                         "meaningful_name": "nota.txt",
                                         "last_analysis_date": 1700000000}}}
VT_HASH_RUIM = {"data": {"attributes": {"last_analysis_stats": {"malicious": 7}}}}

h_limpo = reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "-", "0")
check(h_limpo["status"] == "clean", "hash com todas as fontes respondendo e nada achado -> clean")
check(h_limpo["nome_arquivo"] == "nota.txt", "nome do arquivo vem do VirusTotal")
check(reputacao.build_hash_result("a" * 32, VT_HASH_RUIM, "-", "0")["status"] == "bad",
      "hash detectado pelo VirusTotal -> bad")
check(reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "high", "0",
                                  estado_ibm=core.FONTE_OK)["status"] == "bad",
      "X-Force 'high' basta para bad")
check(reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "-", "4")["status"] == "bad",
      "pulso no AlienVault basta para bad")
h_vt_fora = reputacao.build_hash_result("a" * 32, None, "-", "0",
                                        estado_vt=core.FONTE_INDISPONIVEL)
check(h_vt_fora["status"] == "incompleto", "VirusTotal fora do ar -> incompleto, NAO clean")
check(h_vt_fora["vt_score"] is None, "score de hash sem resposta e None, nunca 0")
h_sem_registro = reputacao.build_hash_result("a" * 32, {}, "-", "0")
check(h_sem_registro["status"] == "clean" and h_sem_registro["estados"]["vt"] == core.FONTE_SEM_DADOS,
      "200 sem atributos -> sem dados, e ninguem acusou nada")

u_limpo = reputacao.build_url_result("exemplo.com", 0, "-", "0")
check(u_limpo["status"] == "clean", "dominio com tudo respondendo e nada achado -> clean")
check(reputacao.build_url_result("exemplo.com", 3, "-", "0")["status"] == "bad",
      "dominio detectado pelo VirusTotal -> bad")
check(reputacao.build_url_result("exemplo.com", 0, "8.6", "0",
                                 estado_ibm=core.FONTE_OK)["status"] == "bad",
      "nota do X-Force >= 2 -> bad")
check(reputacao.build_url_result("exemplo.com", 0, "1.0", "0",
                                 estado_ibm=core.FONTE_OK)["status"] == "clean",
      "nota do X-Force baixa nao acusa sozinha")
u_fora = reputacao.build_url_result("exemplo.com", None, "-", None,
                                    estado_vt=core.FONTE_COTA, estado_alien=core.FONTE_COTA)
check(u_fora["status"] == "incompleto", "dominio com cota estourada -> incompleto, NAO clean")
check(u_fora["fontes_indisponiveis"] == ["VirusTotal", "AlienVault"], "aponta quais fontes faltaram")

print("\n[6c] X-Force de IP: pagina que nao renderiza vira incompleto, nao 'limpo'")
navegador.ESPERA_PAGINA = 0.3   # 18 em producao
navegador.PISO_XFORCE_IP = 0    # 2.0 em producao


class DriverFake:
    """So o que check_ip_ibm toca do driver. Nenhum Chrome e iniciado."""

    def __init__(self, html, renderiza=True):
        self.page_source = html
        self._renderiza = renderiza
        self.window_handles = ["principal", "aba"]
        self.switch_to = SimpleNamespace(window=lambda _h: None)

    def execute_script(self, *_a):
        pass

    def find_element(self, _by, valor):
        if not self._renderiza:
            raise NoSuchElementException(valor)
        return object()

    def close(self):
        self.window_handles = ["principal"]


PLACAR = '<h1 class="risklevelbar high"><span class="numtitle">8.5</span></h1>'

_ip, nota = navegador.check_ip_ibm(DriverFake(PLACAR), "1.1.1.1")
check(nota == 8.5, "placar renderizado e lido como nota numerica")

inicio = time.monotonic()
_ip, lenta = navegador.check_ip_ibm(DriverFake("<body>carregando</body>", renderiza=False),
                                    "1.1.1.1")
decorrido = time.monotonic() - inicio
check(lenta == "error", "pagina que nao renderiza no prazo -> 'error', NAO 'unknown'")
check(reputacao.classificar_ibm(lenta) == core.FONTE_INDISPONIVEL,
      "'error' entra em ESTADOS_SEM_RESPOSTA e bloqueia a conclusao")
lenta_result = reputacao.build_ip_result("1.1.1.1", ABUSE_LIMPO, VT_LIMPO, lenta, "c", "p", "d",
                                         estado_ibm=reputacao.classificar_ibm(lenta))
check(lenta_result["status"] == "incompleto",
      "X-Force lento com as demais fontes limpas -> incompleto, NAO clean")
check(decorrido < 2, f"espera e por evento, nao sleep cego ({decorrido:.1f}s)")

_ip, ilegivel = navegador.check_ip_ibm(DriverFake(
    '<h1 class="risklevelbar"><span class="numtitle">--</span></h1>'), "1.1.1.1")
check(ilegivel == "error", "placar presente mas ilegivel -> 'error', nao nota inventada")

_ip, por_classe = navegador.check_ip_ibm(DriverFake('<h1 class="risklevelbar high"></h1>'),
                                         "1.1.1.1")
check(por_classe == "high", "sem numero, a classe de risco ainda e lida")

print("\n[6d] Dominio digitado passa pelo mesmo rigor do IP e do hash")
for bruto, esperado in [
    ("exemplo.com", "exemplo.com"),
    ("https://sub.exemplo.com.br/caminho?x=1", "sub.exemplo.com.br"),
    ("exemplo.com:8080", "exemplo.com"),
]:
    check(reputacao.extrair_dominio(bruto) == esperado,
          f"{bruto!r} normalizado para {esperado!r}")
for bom in ("exemplo.com", "EXEMPLO.COM", "a-b.co", "xn--p1ai.xn--p1ai", "sub.exemplo.com.br"):
    check(reputacao.dominio_valido(bom), f"{bom!r} aceito")
for ruim in ("", "   ", "localhost", "-mau.com", "mau-.com", "exemplo..com",
             "ex_emplo.com", "exemplo.c", "nao e dominio"):
    check(not reputacao.dominio_valido(ruim), f"{ruim!r} recusado")
check(not reputacao.dominio_valido("1.2.3.4"),
      "IPv4 nao passa por dominio -- TLD precisa ser alfabetico, e IP tem aba propria")

contagem = apresentacao.contar_dominios("exemplo.com, lixo colado, https://ok.com.br")
check(t("count_valid") in contagem and t("count_invalid") in contagem,
      f"contador separa valido de invalido como as outras abas ({contagem})")
check(apresentacao.contar_dominios("") == "", "campo vazio nao mostra contador")

print("\n[7] AlienVault: 404 e zero pulsos, nao indisponibilidade")
mockar(RespostaFake(404))
_score, _link, estado = core.check_hash_alienvault("a" * 32)
check((_score, estado) == ("0", core.FONTE_OK), "indicador ausente do OTX -> 0 pulsos, fonte ok")
mockar(RespostaFake(429))
_score, _link, estado = core.check_hash_alienvault("a" * 32)
check(_score is None and estado == core.FONTE_COTA, "429 no OTX -> sem score e cota")

print("\n[8] VirusTotal de URL separa 'nao catalogada' de 'falhou'")
mockar(RespostaFake(404))
dados, estado = core.check_url_virustotal("exemplo.com")
check(dados["not_found"] and estado == core.FONTE_SEM_DADOS, "404 -> not_found / sem dados")
mockar(RespostaFake(429))
dados, estado = core.check_url_virustotal("exemplo.com")
check(dados["score"] is None and estado == core.FONTE_COTA, "429 -> score None e cota")

print("\n[9] A tela nao mostra 0% para fonte que falhou")
root = tk.Tk()
tema.configurar_estilos(ttk.Style())
root.withdraw()
app = gui.IPCheckerApp(root)
gui.app = app

texto = apresentacao.relatorio_ip(abuse_fora)
check(t("source_unavailable") in texto, "detalhe diz 'falha na consulta'")
check("0%" not in texto, "detalhe nao inventa 0%")
check(t("sources_incomplete").split("{")[0].strip() in texto, "detalhe lista as fontes que faltaram")
check(apresentacao.texto_fonte(0, core.FONTE_OK, "%") == "0%", "fonte que respondeu 0 mostra 0%")
check(apresentacao.coluna_fonte(None, core.FONTE_COTA) == "!", "celula marca a falha com !")
check(apresentacao.colunas_ip(abuse_fora, "BR")[1] == t("verdict_incomplete"), "veredito da linha e incompleto")

print("\n[10] Pre-analise nao declara 'nada encontrado' com fonte faltando")
app.results_ip = [["1.1.1.1"]]
app.pre_var_ip.set(True)
app.bad_ips, app.review_ips, app.ignorados_ip = set(), set(), []
app.incompletos_ip, app.cota_ip = set(), set()
app._append_analysis()
check(t("ip_clean_one") in app.tabela_ip.report(), "sem pendencia, declara limpo normalmente")

app.incompletos_ip = {"1.1.1.1"}
app._append_analysis()
relatorio = app.tabela_ip.report()
check(t("ip_clean_one") not in relatorio, "com fonte faltando, NAO declara limpo")
check("1.1.1.1" in relatorio and t("incomplete_review").split("{")[0].strip() in relatorio,
      "avisa quais itens ficaram incompletos")

app.cota_ip = {"VirusTotal"}
app._append_analysis()
relatorio = app.tabela_ip.report()
check(t("quota_warning").split("{")[0].strip() in relatorio, "avisa que a cota estourou")
check("VirusTotal" in relatorio, "diz qual API esgotou")

print("\n[11] Exportacao tambem nao mente")
linha = apresentacao.linha_planilha_ip(abuse_fora, com_ibm=False)
check(t("source_unavailable") in linha, "planilha registra a falha da fonte")
check("0%" not in linha, "planilha nao grava 0% inventado")
linha_hash = apresentacao.linha_planilha_hash(h_vt_fora, com_ibm=False)
check(t("source_unavailable") in linha_hash, "planilha de hash registra a falha da fonte")
check(len(linha_hash) == len(apresentacao.linha_planilha_hash(h_vt_fora, com_ibm=True)) - 2,
      "coluna e link do X-Force somem juntos quando a fonte esta desligada")
linha_url = apresentacao.linha_planilha_url(u_fora, com_ibm=False)
check(t("source_quota") in linha_url, "planilha de dominio registra a cota estourada")
check("0" not in linha_url[1], "planilha de dominio nao grava 0 inventado")

print("\n[12] A tela de hash e dominio tambem nao mente")
texto_hash = apresentacao.relatorio_hash(h_vt_fora, com_ibm=False)
check(t("source_unavailable") in texto_hash, "detalhe do hash diz 'falha na consulta'")
check(apresentacao.colunas_hash(h_vt_fora, com_ibm=False)[1] == t("verdict_incomplete"),
      "veredito da linha de hash e incompleto")
check(apresentacao.colunas_hash(h_limpo, com_ibm=False)[5] == "nota.txt",
      "coluna de arquivo traz o nome do VirusTotal")
check(apresentacao.colunas_hash(h_vt_fora, com_ibm=False)[5] == "-",
      "sem resposta do VirusTotal, a coluna de arquivo fica vazia")
check(apresentacao.colunas_url(u_fora, com_ibm=False)[1] == t("verdict_incomplete"),
      "veredito da linha de dominio e incompleto")

root.destroy()
encerrar()
