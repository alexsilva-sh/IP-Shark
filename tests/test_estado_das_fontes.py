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
from ui import fontes as catalogo

TODAS = {aba: catalogo.todas(aba) for aba in ("ip", "hash", "url")}
SEM_IBM = {aba: fontes - {"ibm"} for aba, fontes in TODAS.items()}

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
core.PAUSA_RETENTATIVA = 0   # a pausa entre tentativas nao precisa ser vivida aqui

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

print("\n[2b] Sessao reaproveitada, com uma unica politica de retentativa")
sessao = _sessao_real()
check(sessao is _sessao_real(), "a mesma thread reaproveita a Session (keep-alive)")
de_outra_thread = []
aux = threading.Thread(target=lambda: de_outra_thread.append(_sessao_real()))
aux.start()
aux.join()
check(de_outra_thread[0] is not sessao,
      "cada thread tem a sua -- Session do requests nao e thread-safe")
recuo = sessao.get_adapter("https://exemplo").max_retries
check(recuo.total == 0,
      f"urllib3 nao retenta: multiplicaria com o laco de _consultar (total={recuo.total})")

print("\n[2b2] Fonte indisponivel e retentada; o resto sai na primeira resposta")
for resposta, tentativas_esperadas, msg in (
    (RespostaFake(500), core.TENTATIVAS_FONTE, "5xx retenta"),
    (requests.exceptions.Timeout(), core.TENTATIVAS_FONTE, "timeout retenta"),
    (RespostaFake(200, quebrado=True), core.TENTATIVAS_FONTE, "corpo ilegivel retenta"),
    (RespostaFake(429), 1, "cota nao retenta -- nao melhora insistindo"),
    (RespostaFake(401), 1, "chave recusada nao retenta"),
    (RespostaFake(404), 1, "'sem registros' e resposta valida, nao retenta"),
    (RespostaFake(200, {"a": 1}), 1, "acerto de primeira nao gasta tentativa extra"),
):
    mockar(resposta)
    del chamadas[:]
    core._consultar("https://exemplo")
    check(len(chamadas) == tentativas_esperadas,
          f"{msg} ({len(chamadas)} de {tentativas_esperadas} tentativas)")

mockar(RespostaFake(500))
del chamadas[:]
core.definir_cancelamento(lambda: True)
core._consultar("https://exemplo")
check(len(chamadas) == 1, "varredura cancelada nao continua insistindo")
core.definir_cancelamento(None)

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

print("\n[2d] Cota restante e lida do cabecalho, e nunca inventada")
mockar(RespostaFake(200, {"data": {}}, headers={"X-RateLimit-Remaining": "873"}))
core.check_ip_abuseipdb("8.8.8.8")
check(core.cotas_restantes().get("AbuseIPDB") == 873, "restante veio do cabecalho")
mockar(RespostaFake(200, {"data": {}}))
core.check_ip_virustotal("8.8.8.8")
check("VirusTotal" not in core.cotas_restantes(),
      "API que nao informa cota nao aparece -- rodape vazio nao e cota zerada")
mockar(RespostaFake(429, headers={"Retry-After": "60"}))
core.check_ip_abuseipdb("8.8.8.8")
check(core.cotas_restantes().get("AbuseIPDB") == 0, "429 zera o restante da fonte")

print("\n[2e] Teste de conexao por servico usa a chave digitada, nao a salva")
mockar(RespostaFake(200, {"data": {}}))
resultado = core.testar_fontes({"ABUSEIPDB_API_KEY": "digitada", "VIRUSTOTAL_API_KEY": "  "})
check(resultado == {"ABUSEIPDB_API_KEY": core.FONTE_OK},
      f"so a chave preenchida e testada ({resultado})")
enviados = chamadas[-1]
check(enviados["headers"]["Key"] == "digitada", "a chave testada e a que veio do campo")
check(core.IP_TESTE not in ("", None) and enviados["params"]["ipAddress"] == core.IP_TESTE,
      "sonda usa um IP publico fixo, nao dado de cliente")
mockar(RespostaFake(401))
check(core.testar_fontes({"ABUSEIPDB_API_KEY": "errada"}) == {"ABUSEIPDB_API_KEY": core.FONTE_SEM_CHAVE},
      "401 vira 'chave recusada' em vez de falha generica")
mockar(RespostaFake(404))
check(core.testar_fontes({"ALIENVAULT_API_KEY": "k"}) == {"ALIENVAULT_API_KEY": core.FONTE_OK},
      "404 prova que a chave passou e a fonte respondeu")
mockar(requests.exceptions.ConnectionError())
check(core.testar_fontes({"IPINFO_API_KEY": "k"}) == {"IPINFO_API_KEY": core.FONTE_INDISPONIVEL},
      "sem rede o teste acusa indisponivel, nao chave ruim")

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
OTX_ZERO = core._otx_contexto({})

h_limpo = reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "-", OTX_ZERO)
check(h_limpo["status"] == "clean", "hash com todas as fontes respondendo e nada achado -> clean")
check(h_limpo["nome_arquivo"] == "nota.txt", "nome do arquivo vem do VirusTotal")
check(reputacao.build_hash_result("a" * 32, VT_HASH_RUIM, "-", OTX_ZERO)["status"] == "bad",
      "hash detectado pelo VirusTotal -> bad")
check(reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "high", OTX_ZERO,
                                  estado_ibm=core.FONTE_OK)["status"] == "bad",
      "X-Force 'high' basta para bad")
OTX_EMOTET = core._otx_contexto({"pulse_info": {"count": 4, "pulses": [
    {"name": "Emotet C2 infrastructure", "adversary": "TA542",
     "malware_families": [{"display_name": "Emotet"}],
     "attack_ids": [{"display_name": "T1071 - Application Layer Protocol"}]}]}})
h_otx = reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "-", OTX_EMOTET)
check(h_otx["status"] == "clean",
      "pulso no AlienVault NAO acusa sozinho: e mencao da comunidade, nao deteccao")
check(h_otx["alien"]["familias"] == ["Emotet"] and h_otx["alien"]["adversarios"] == ["TA542"],
      "mas a familia e o grupo entram no resultado -- e o que so o OTX entrega")
check(reputacao.build_url_result("google.com", 0, "1.0",
                                 core._otx_contexto({"pulse_info": {"count": 50}}),
                                 estado_ibm=core.FONTE_OK)["status"] == "clean",
      "google.com com 50 pulsos e VT/X-Force limpos nao vira malicioso")
h_vt_fora = reputacao.build_hash_result("a" * 32, None, "-", OTX_ZERO,
                                        estado_vt=core.FONTE_INDISPONIVEL)
check(h_vt_fora["status"] == "incompleto", "VirusTotal fora do ar -> incompleto, NAO clean")
check(h_vt_fora["vt_score"] is None, "score de hash sem resposta e None, nunca 0")
h_sem_registro = reputacao.build_hash_result("a" * 32, {}, "-", OTX_ZERO)
check(h_sem_registro["estados"]["vt"] == core.FONTE_SEM_DADOS,
      "200 sem atributos -> sem dados")
check(h_sem_registro["status"] == "sem_registros",
      "nenhuma base conhece o hash -> 'Sem registros', NAO 'Limpo'")
check(apresentacao.colunas_hash(h_sem_registro, SEM_IBM["hash"])[1] == t("verdict_no_records"),
      "a coluna de veredito diz o mesmo que o cabecalho do relatorio")
check(t("no_records") in apresentacao.relatorio_hash(h_sem_registro, SEM_IBM["hash"]).splitlines()[0],
      "e o relatorio nao afirma que o arquivo e legitimo")
check(apresentacao.VERDICT_TAGS["sem_registros"] != apresentacao.VERDICT_TAGS["clean"],
      "na tabela nao sai em verde de limpo")

# Uma fonte que analisou e nao achou nada ainda vale como limpo.
h_uma_analisou = reputacao.build_hash_result("a" * 32, {}, "-", OTX_ZERO,
                                             md={"detectados": 0, "total": 20},
                                             estado_md=core.FONTE_OK)
check(h_uma_analisou["status"] == "clean",
      "com o MetaDefender analisando e achando zero, segue limpo")
SEM = core.FONTE_SEM_DADOS
for nome, data, colunas in (
    ("IP", reputacao.build_ip_result("1.2.3.4", None, None, None, "c", "p", "d",
                                     estado_abuse=SEM, estado_vt=SEM, estado_ibm=SEM,
                                     estado_md=SEM),
     lambda d: apresentacao.colunas_ip(d, "-", TODAS["ip"])),
    ("hash", reputacao.build_hash_result("a" * 40, {}, "-", OTX_ZERO, estado_ibm=SEM,
                                        estado_md=SEM),
     lambda d: apresentacao.colunas_hash(d, TODAS["hash"])),
    ("dominio", reputacao.build_url_result("nunca-vista.com", None, "-", OTX_ZERO,
                                          estado_vt=SEM, estado_ibm=SEM, estado_md=SEM),
     lambda d: apresentacao.colunas_url(d, TODAS["url"])),
):
    check(data["status"] == "sem_registros" and colunas(data)[1] == t("verdict_no_records"),
          f"a regra vale para {nome}, nao so para hash")

u_limpo = reputacao.build_url_result("exemplo.com", 0, "-", OTX_ZERO)
check(u_limpo["status"] == "clean", "dominio com tudo respondendo e nada achado -> clean")
check(reputacao.build_url_result("exemplo.com", 3, "-", OTX_ZERO)["status"] == "bad",
      "dominio detectado pelo VirusTotal -> bad")
check(reputacao.build_url_result("exemplo.com", 0, "8.6", OTX_ZERO,
                                 estado_ibm=core.FONTE_OK)["status"] == "bad",
      "nota do X-Force >= 2 -> bad")
check(reputacao.build_url_result("exemplo.com", 0, "1.0", OTX_ZERO,
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

print("\n[6e] MetaDefender: contagem de quem acusou, com o total quando existe")
core.METADEFENDER_API_KEY = "k"
MD_HASH = {"scan_results": {"total_detected_avs": 12, "total_avs": 20}}
MD_IP = {"lookup_results": {"detected_by": 2,
                            "sources": [{"provider": "webroot", "assessment": "malicious"},
                                        {"provider": "x", "assessment": "phishing"}]}}
mockar(RespostaFake(200, MD_HASH))
md, estado = core.check_hash_metadefender("a" * 32)
check((md["detectados"], md["total"], estado) == (12, 20, core.FONTE_OK),
      f"hash: le motores que acusaram e total de motores ({md})")
check(apresentacao.md_placar({"md": md}) == "12/20",
      "a tela mostra a proporcao, nao o numero solto")
mockar(RespostaFake(200, MD_IP))
md_ip, estado = core.check_ip_metadefender("8.8.8.8")
check((md_ip["detectados"], md_ip["total"], estado) == (2, None, core.FONTE_OK),
      "IP: le a contagem de listas de reputacao, que nao tem total")
check(md_ip["avaliacoes"] == ["malicious", "phishing"], "guarda o que cada lista disse")
check(apresentacao.md_placar({"md": md_ip}) == "2", "sem total, mostra so a contagem")

mockar(RespostaFake(200, {"algo": "que nao sabemos ler"}))
md_estranho, estado = core.check_hash_metadefender("a" * 32)
check(md_estranho is None and estado == core.FONTE_INDISPONIVEL,
      "200 em formato desconhecido vira fonte sem resposta, NAO zero deteccao")
mockar(RespostaFake(404))
_md, estado = core.check_hash_metadefender("a" * 32)
check(estado == core.FONTE_SEM_DADOS, "404: hash que o MetaDefender nao conhece e 'sem registros'")

print("\n[6f] Deteccao do MetaDefender decide veredito nas tres abas")
h_md = reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "-", OTX_ZERO,
                                   md={"detectados": 12, "total": 20}, estado_md=core.FONTE_OK)
check(h_md["status"] == "bad", "hash limpo no VT mas acusado por 12 motores -> bad")
u_md = reputacao.build_url_result("mau.com", 0, "1.0", OTX_ZERO, estado_ibm=core.FONTE_OK,
                                  md={"detectados": 3}, estado_md=core.FONTE_OK)
check(u_md["status"] == "bad", "dominio acusado por 3 listas -> bad")
ip_md = reputacao.build_ip_result("9.9.9.9", ABUSE_LIMPO, VT_LIMPO, None, "c", "p", "d",
                                  estado_ibm=None, md={"detectados": 1}, estado_md=core.FONTE_OK)
check(ip_md["status"] == "bad", "IP acusado por 1 lista -> bad")
ip_md_limpo = reputacao.build_ip_result("9.9.9.9", ABUSE_LIMPO, VT_LIMPO, None, "c", "p", "d",
                                        estado_ibm=None, md={"detectados": 0, "total": 20},
                                        estado_md=core.FONTE_OK)
check(ip_md_limpo["status"] == "clean", "zero deteccao com tudo respondendo -> clean")
ip_md_fora = reputacao.build_ip_result("9.9.9.9", ABUSE_LIMPO, VT_LIMPO, None, "c", "p", "d",
                                       estado_ibm=None, estado_md=core.FONTE_INDISPONIVEL)
check(ip_md_fora["status"] == "incompleto" and
      "MetaDefender" in ip_md_fora["fontes_indisponiveis"],
      "MetaDefender fora do ar -> incompleto, NAO clean")
ip_sem_md = reputacao.build_ip_result("9.9.9.9", ABUSE_LIMPO, VT_LIMPO, None, "c", "p", "d",
                                      estado_ibm=None)
check(ip_sem_md["status"] == "clean" and not ip_sem_md["fontes_indisponiveis"],
      "fonte nao consultada nao vira fonte faltando")
check(reputacao.LINK_MD in apresentacao.relatorio_ip(ip_md) and
      reputacao.LINK_MD in apresentacao.relatorio_hash(h_md) and
      reputacao.LINK_MD in apresentacao.relatorio_url(u_md),
      "o relatorio das tres abas leva o link do MetaDefender")
check(ip_sem_md["links"]["md"] is None and
      reputacao.LINK_MD not in apresentacao.relatorio_ip(ip_sem_md),
      "sem consultar a fonte, o link nao entra no relatorio")

print("\n[7] AlienVault: contexto no lugar da contagem crua")
mockar(RespostaFake(404))
alien, _link, estado = core.check_hash_alienvault("a" * 32)
check((alien["pulsos"], estado) == (0, core.FONTE_OK),
      "indicador ausente do OTX -> 0 pulsos, fonte ok")
mockar(RespostaFake(429))
alien, _link, estado = core.check_hash_alienvault("a" * 32)
check(alien is None and estado == core.FONTE_COTA, "429 no OTX -> sem contexto e cota")

OTX_COMPLETO = {"pulse_info": {"count": 7, "pulses": [
    {"name": "Despejo de IOCs de hoje", "modified": "2026-07-28T10:00:00"},
    {"name": "Campanha TA577", "modified": "2026-01-05T10:00:00",
     "malware_families": ["Qakbot", {"display_name": "Cobalt Strike"}], "adversary": "TA577",
     "attack_ids": [{"id": "T1204", "display_name": "T1204 - User Execution"}]},
    {"name": "Relato sem data"}]},
    "validation": [{"source": "alexa", "name": "Alexa top 1M"}]}
mockar(RespostaFake(200, OTX_COMPLETO))
alien, _link, estado = core.check_hash_alienvault("a" * 32)
check(alien["familias"] == ["Qakbot", "Cobalt Strike"],
      f"familia sai tanto de texto quanto de objeto, sem repetir ({alien['familias']})")
check(alien["adversarios"] == ["TA577"], "grupo atribuido entra no resultado")
check("tecnicas" not in alien, "tecnica MITRE nao e mais coletada")
check(alien["titulo"] == "Campanha TA577",
      f"vale o relato que informa, nao o mais recente ({alien['titulo']!r})")

recencia = core._otx_contexto({"pulse_info": {"pulses": [
    {"name": "Qakbot antigo", "malware_families": ["Qakbot"], "modified": "2026-01-01"},
    {"name": "Qakbot recente", "malware_families": ["Qakbot"], "modified": "2026-07-01"}]}})
check(recencia["titulo"] == "Qakbot recente",
      f"entre relatos igualmente informativos, o mais recente ({recencia['titulo']!r})")
sem_nada = core._otx_contexto({"pulse_info": {"pulses": [
    {"name": "Despejo antigo", "modified": "2026-01-01"},
    {"name": "Despejo recente", "modified": "2026-07-01"}]}})
check(sem_nada["titulo"] == "Despejo recente",
      "sem nada que informe, a data volta a decidir")
check(alien["legitimo"] == ["Alexa top 1M"],
      "a lista de legitimos do OTX e lida -- e o sinal que faltava no google.com")

dados_otx = reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "-", alien)
linha_av = apresentacao.linha_alienvault(dados_otx, core.FONTE_OK)
check(linha_av.startswith(f"{t('alien_score')}: 7 {t('count_pulses')}") and
      t("otx_pulses") in linha_av and "Campanha TA577" in linha_av,
      f"contagem e relato na mesma linha da fonte ({linha_av})")
check("(+6)" in linha_av, "e diz quantos outros relatos existem, em vez de enfileirar titulos")
um_so = reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "-",
                                    core._otx_contexto({"pulse_info": {"count": 1, "pulses": [
                                        {"name": "TrojanDownloader:Win32/Tsunovest.A"}]}}))
check(apresentacao.linha_alienvault(um_so, core.FONTE_OK) ==
      f"{t('alien_score')}: 1 {t('count_pulse')} | {t('otx_pulses')} "
      "TrojanDownloader:Win32/Tsunovest.A",
      "com um unico relato nao sobra '(+0)' nem plural errado")
check("|" not in apresentacao.linha_alienvault(dados_otx, core.FONTE_INDISPONIVEL),
      "fonte que falhou nao ganha relato: a linha diz so que falhou")

linhas = apresentacao.linhas_otx(dados_otx)
check(any(t("otx_family") in linha and "Qakbot" in linha for linha in linhas),
      "familia continua em linha propria, agregada de todos os pulses")
check(any(t("otx_adversary") in linha and "TA577" in linha for linha in linhas),
      "e o grupo atribuido")
check(not any(t("otx_pulses") in linha for linha in linhas),
      "o relato saiu das linhas soltas -- agora vive junto da contagem")
check(apresentacao.alien_coluna(dados_otx) == "Qakbot",
      "a celula mostra a familia do relato escolhido, nao o numero de pulsos")
check(apresentacao.alien_coluna(reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "-", OTX_ZERO))
      == "0", "sem familia conhecida, a celula volta a contagem")
check(not apresentacao.linhas_otx(reputacao.build_hash_result("a" * 32, VT_HASH_LIMPO, "-", OTX_ZERO)),
      "indicador sem contexto nao gera linha vazia no relatorio")

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
avisos = app.tabela_ip.warnings()
check(t("ip_clean_one") not in relatorio, "com fonte faltando, NAO declara limpo")
check("1.1.1.1" in avisos and t("incomplete_review").split("{")[0].strip() in avisos,
      "avisa quais itens ficaram incompletos")
check(t("incomplete_review").split("{")[0].strip() not in relatorio,
      "o aviso fica na tela e fora do texto copiado -- o analista cola para o cliente")
check(t("warnings_not_copied") in app.tabela_ip.detalhe.get("1.0", tk.END),
      "a tela diz que aquele bloco nao vai no relatorio")

app.cota_ip = {"VirusTotal"}
app._append_analysis()
avisos = app.tabela_ip.warnings()
check(t("quota_warning").split("{")[0].strip() in avisos, "avisa que a cota estourou")
check("VirusTotal" in avisos, "diz qual API esgotou")
check(t("quota_warning").split("{")[0].strip() not in app.tabela_ip.report(),
      "aviso de cota tambem nao entra no texto copiado")

print("\n[10b] A lista de IPs para bloqueio vai sem espaco")
app.incompletos_ip, app.cota_ip = set(), set()
app.bad_ips = {"34.68.34.89", "78.153.140.177"}
app.mss_var_ip.set(True)
app._append_analysis()
check("34.68.34.89,78.153.140.177" in app.tabela_ip.report(),
      "IPs separados so por virgula: espaco quebra o bloqueio automatico")
app.bad_ips = set()
app.mss_var_ip.set(False)

print("\n[11] Exportacao tambem nao mente")
linha = apresentacao.linha_planilha_ip(abuse_fora, SEM_IBM["ip"])
check(t("source_unavailable") in linha, "planilha registra a falha da fonte")
check("0%" not in linha, "planilha nao grava 0% inventado")
linha_hash = apresentacao.linha_planilha_hash(h_vt_fora, SEM_IBM["hash"])
check(t("source_unavailable") in linha_hash, "planilha de hash registra a falha da fonte")
check(len(linha_hash) == len(apresentacao.linha_planilha_hash(h_vt_fora, TODAS["hash"])) - 2,
      "coluna e link do X-Force somem juntos quando a fonte esta desligada")
linha_url = apresentacao.linha_planilha_url(u_fora, SEM_IBM["url"])
check(t("source_quota") in linha_url, "planilha de dominio registra a cota estourada")
check("0" not in linha_url[1], "planilha de dominio nao grava 0 inventado")

print("\n[12] A tela de hash e dominio tambem nao mente")
texto_hash = apresentacao.relatorio_hash(h_vt_fora, SEM_IBM["hash"])
check(t("source_unavailable") in texto_hash, "detalhe do hash diz 'falha na consulta'")
check(apresentacao.colunas_hash(h_vt_fora, SEM_IBM["hash"])[1] == t("verdict_incomplete"),
      "veredito da linha de hash e incompleto")
check(apresentacao.colunas_hash(h_limpo, SEM_IBM["hash"])[2] == "nota.txt",
      "coluna de arquivo traz o nome do VirusTotal, logo depois do veredito")
check(apresentacao.colunas_hash(h_vt_fora, SEM_IBM["hash"])[2] == "-",
      "sem resposta do VirusTotal, a coluna de arquivo fica vazia")
check(apresentacao.colunas_hash(h_limpo, SEM_IBM["hash"])[-1] != "nota.txt",
      "o arquivo saiu do fim da linha, onde era o primeiro a sair da tela")
check(apresentacao.colunas_url(u_fora, SEM_IBM["url"])[1] == t("verdict_incomplete"),
      "veredito da linha de dominio e incompleto")

root.destroy()
encerrar()
