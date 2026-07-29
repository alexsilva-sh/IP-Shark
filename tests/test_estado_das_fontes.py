"""Estado por fonte: indisponibilidade nunca pode virar 'limpo'.

Todo HTTP e mockado -- nenhuma requisicao real sai daqui.
"""
import tkinter as tk
from tkinter import ttk

from _comum import check, encerrar

import requests
from core import api as core
import app as gui
from core import reputacao
from i18n import t
from ui import apresentacao, tema

gui.IPCheckerApp._init_drivers_async = lambda self, count=3: None

chamadas = []


class RespostaFake:
    def __init__(self, status, payload=None, quebrado=False):
        self.status_code = status
        self._payload = payload or {}
        self._quebrado = quebrado

    def json(self):
        if self._quebrado:
            raise ValueError("json invalido")
        return self._payload


def mockar(resposta):
    """Troca requests.get por algo que devolve `resposta` (ou levanta, se for excecao)."""
    def _fake(url, **kwargs):
        chamadas.append(kwargs)
        if isinstance(resposta, Exception):
            raise resposta
        return resposta
    core.requests.get = _fake


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
