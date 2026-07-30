"""Personalizar pesquisa: fonte desmarcada nao e consultada e nao deixa o resultado incompleto.

Nenhuma requisicao real sai daqui -- as consultas das abas sao substituidas por espioes.
"""
import itertools
import tkinter as tk
from tkinter import ttk

from _comum import bloquear_rede, check, encerrar

import app as gui
from core import api as core
from core import reputacao
from i18n import t
from ui import aba_hash, aba_ip, aba_url, apresentacao, tema
from ui import fontes as catalogo
from ui.dialogo_fontes import DialogoFontes

gui.IPCheckerApp._init_drivers_async = lambda self, count=3: None

ABAS = ("ip", "hash", "url")
OTX_ZERO = core._otx_contexto({})

print("[1] Catalogo fechado: nada aponta para fonte ou coluna que nao existe")
for aba in ABAS:
    chaves = catalogo.todas(aba)
    check(len(chaves) == len(catalogo.CATALOGO[aba]), f"sem chave repetida em {aba}")
    orfas = set(catalogo.COLUNAS[aba]) - chaves
    check(not orfas, f"toda coluna mapeada em {aba} pertence a uma fonte do catalogo ({orfas})")
    check(catalogo.rapidas(aba) and catalogo.rapidas(aba) != chaves,
          f"{aba} tem fontes de API e ao menos uma de navegador")
for aba in ABAS:
    tipos = [tipo for _c, _r, tipo in catalogo.CATALOGO[aba]]
    check(tipos == sorted(tipos, key=lambda x: x != catalogo.API),
          f"as de API vem primeiro em {aba}, para 'so as rapidas' pegar um bloco contiguo")

print("\n[2] Planilha nunca desalinha, em nenhuma combinacao de fontes")
dados = {
    "ip": reputacao.build_ip_result("1.2.3.4", {"data": {"abuseConfidenceScore": 9}},
                                    {"data": {"attributes": {"last_analysis_stats":
                                                             {"malicious": 2}}}},
                                    "high", "Cidade", "Pais", "d.com",
                                    estado_ibm=core.FONTE_OK,
                                    md={"detectados": 1, "total": 20},
                                    estado_md=core.FONTE_OK),
    "hash": reputacao.build_hash_result("a" * 32, {"data": {"attributes": {
        "last_analysis_stats": {"malicious": 3}, "meaningful_name": "x.exe"}}},
        "high", OTX_ZERO, None, estado_ibm=core.FONTE_OK,
        md={"detectados": 1, "total": 20}, estado_md=core.FONTE_OK),
    "url": reputacao.build_url_result("exemplo.com", 4, "8.6", OTX_ZERO,
                                      estado_ibm=core.FONTE_OK,
                                      md={"detectados": 1, "total": 20},
                                      estado_md=core.FONTE_OK),
}
CABECALHO = {"ip": apresentacao.cabecalho_planilha_ip,
             "hash": apresentacao.cabecalho_planilha_hash,
             "url": apresentacao.cabecalho_planilha_url}
LINHA = {"ip": apresentacao.linha_planilha_ip,
         "hash": apresentacao.linha_planilha_hash,
         "url": apresentacao.linha_planilha_url}
for aba in ABAS:
    chaves = sorted(catalogo.todas(aba))
    desalinhadas = []
    for tamanho in range(1, len(chaves) + 1):
        for combinacao in itertools.combinations(chaves, tamanho):
            ativas = set(combinacao)
            if len(CABECALHO[aba](ativas)) != len(LINHA[aba](dados[aba], ativas)):
                desalinhadas.append(ativas)
    total = 2 ** len(chaves) - 1
    check(not desalinhadas,
          f"{aba}: cabecalho e linha batem nas {total} combinacoes ({desalinhadas[:2]})")

print("\n[3] O relatorio nao cita a fonte que nao foi consultada")
so_apis = catalogo.rapidas("hash")
texto = apresentacao.relatorio_hash(dados["hash"], so_apis)
check(t("ibm_score") not in texto, "X-Force desligado nao aparece no relatorio de hash")
check(t("vt_score") in texto, "e o que ficou ligado continua aparecendo")
check(apresentacao.relatorio_hash(dados["hash"], {"ibm"}).count(t("alien_score")) == 0,
      "AlienVault desligado tambem sai do relatorio")
ip_sem_local = apresentacao.relatorio_ip(dados["ip"], fontes=catalogo.todas("ip") - {"local"})
check(t("country_city_label") not in ip_sem_local,
      "sem IPinfo o relatorio de IP nao mostra linha de pais e cidade")
check(t("abuseipdb_score") in ip_sem_local, "mas o AbuseIPDB segue la")

print("\n[4] Coluna da tabela vira '-' e o veredito nao mente")
colunas = apresentacao.colunas_hash(dados["hash"], so_apis)
check(colunas[4] == "-", f"celula do X-Force desligado fica vazia ({colunas[4]})")
check(colunas[3] != "-", "a do VirusTotal, ligada, tem placar")

root = tk.Tk()
tema.configurar_estilos(ttk.Style())
root.withdraw()
app = gui.IPCheckerApp(root)
gui.app = app

print("\n[5] Um botao por aba, e o resumo diz o que ficou de fora")
for aba, botao in (("ip", app.botao_fontes_ip), ("hash", app.botao_fontes_hash),
                   ("url", app.botao_fontes_url)):
    check(botao._texto == t("btn_customize"), f"aba de {aba} tem o botao unico")
check(app.fontes_ip == catalogo.todas("ip"), "comeca com todas as fontes marcadas")
check(app._resumo_fontes("ip", catalogo.todas("ip")) == "",
      "com tudo ligado o resumo fica vazio, sem poluir a tela")
resumo = app._resumo_fontes("hash", catalogo.rapidas("hash"))
check(t("source_ibm") in resumo and t("source_joe") in resumo,
      f"o resumo nomeia as fontes desligadas ({resumo})")
check(t("source_vt") not in resumo, "e nao cita as que continuam ligadas")

print("\n[6] Aplicar no modal esconde a coluna e guarda a escolha")
app._aplicar_fontes_hash(catalogo.rapidas("hash"))
visiveis = app.tabela_hash.tree.cget("displaycolumns")
check("ibm" not in visiveis and "joe" not in visiveis,
      f"colunas das fontes de navegador sairam da tabela ({visiveis})")
check("vt" in visiveis and "alien" in visiveis, "as de API continuam visiveis")
app._aplicar_fontes_hash(catalogo.todas("hash"))
check("ibm" in app.tabela_hash.tree.cget("displaycolumns"),
      "religar a fonte traz a coluna de volta")

print("\n[7] O modal: atalhos, minimo de uma fonte e retorno da escolha")
escolhas = []
dlg = DialogoFontes(root, "hash", catalogo.todas("hash"), escolhas.append)
check(set(dlg.vars) == catalogo.todas("hash"), "lista as fontes da aba pedida")
dlg._marcar_rapidas()
check(dlg.selecionadas() == catalogo.rapidas("hash"), "'so as rapidas' deixa apenas as de API")
dlg._marcar_todas()
check(dlg.selecionadas() == catalogo.todas("hash"), "'marcar todas' volta tudo")
for var in dlg.vars.values():
    var.set(False)
avisos = []
import ui.dialogo_fontes as mod_dlg
mod_dlg.messagebox.showwarning = lambda *a, **kw: avisos.append(a)
dlg._aplicar()
check(avisos and not escolhas, "sem nenhuma fonte o modal avisa e nao aplica")
check(dlg.winfo_exists(), "e a janela fica aberta para o usuario corrigir")
dlg.vars["vt"].set(True)
dlg._aplicar()
check(escolhas == [{"vt"}], f"aplicar devolve o conjunto escolhido ({escolhas})")

print("\n[8] Fonte desmarcada nao e consultada")
consultadas = []


def espiao(nome, retorno):
    def _fake(*_a, **_kw):
        consultadas.append(nome)
        return retorno
    return _fake


VT_IP = ({"data": {"attributes": {"last_analysis_stats": {"malicious": 0}}}}, core.FONTE_OK)
aba_ip.check_ip_abuseipdb = espiao("abuse", ({"data": {"abuseConfidenceScore": 0}}, core.FONTE_OK))
aba_ip.check_ip_virustotal = espiao("vt", VT_IP)
aba_ip.check_ip_metadefender = espiao("md", ({"detectados": 0, "total": 20}, core.FONTE_OK))
aba_ip.get_location = espiao("local", ("Cidade", "Pais"))
app._consultar_ibm = lambda consulta, alvo: (consultadas.append("ibm"), ("low", core.FONTE_OK))[1]
bloquear_rede(core)

app.fontes_ip_varredura = {"vt"}
resultado = app._consultar_ip(1, "8.8.8.8", 1)
check(consultadas == ["vt"], f"so o VirusTotal foi chamado ({consultadas})")
data = resultado[6]
check(data["estados"] == {"abuse": None, "vt": core.FONTE_OK, "ibm": None, "md": None},
      f"fonte nao consultada chega como estado None ({data['estados']})")
check(not data["fontes_indisponiveis"],
      "e None nao entra em fontes_indisponiveis -- desligar nao e estar fora do ar")
check(data["status"] == "clean",
      f"com o VirusTotal respondendo e nada achado, o veredito e limpo ({data['status']})")

del consultadas[:]
app.fontes_ip_varredura = catalogo.todas("ip")
app._consultar_ip(1, "8.8.8.8", 1)
check(sorted(consultadas) == ["abuse", "ibm", "local", "md", "vt"],
      f"com tudo marcado, todas as fontes sao consultadas ({sorted(consultadas)})")

print("\n[9] O mesmo vale para hash e dominio")
del consultadas[:]
aba_hash.check_hash_virustotal = espiao("vt", (None, core.FONTE_SEM_DADOS))
aba_hash.check_hash_alienvault = espiao("alien", (OTX_ZERO, "link", core.FONTE_OK))
aba_hash.check_hash_metadefender = espiao("md", (None, core.FONTE_SEM_DADOS))
aba_hash.check_hash_joesandbox = espiao("joe", (None, "link"))
app.results_hash = []
app.fontes_hash_varredura = {"vt", "md"}
_texto, status, _colunas, estados = app.process_hash("a" * 32, 1)
check(sorted(consultadas) == ["md", "vt"], f"hash consulta so o marcado ({consultadas})")
check(estados["alien"] is None and estados["ibm"] is None,
      "AlienVault e X-Force desmarcados ficam com estado None")
check(status == "sem_registros" and "JoeSandbox" not in _texto,
      f"nem o JoeSandbox aparece ({status})")

del consultadas[:]
aba_url.check_url_virustotal = espiao("vt", ({"score": 0}, core.FONTE_OK))
aba_url.check_url_alienvault = espiao("alien", (OTX_ZERO, "link", core.FONTE_OK))
aba_url.check_dominio_metadefender = espiao("md", (None, core.FONTE_SEM_DADOS))
app.fontes_url_varredura = {"vt", "ips"}
data_url = app._consultar_dominio("exemplo.com")
check(consultadas == ["vt"], f"dominio consulta so o marcado ({consultadas})")
check(not data_url["fontes_indisponiveis"] and data_url["status"] == "clean",
      f"e o veredito sai limpo, nao incompleto ({data_url['status']})")

print("\n[10] Na aba de dominio, a escolha desce para os IPs resolvidos")
app.fontes_url_varredura = {"vt", "ips"}
herdadas = app._fontes_ip_associado()
check("md" not in herdadas and "ibm" not in herdadas,
      f"MetaDefender e X-Force desligados nao sao consultados nos IPs ({herdadas})")
check({"abuse", "local", "vt"} <= herdadas,
      "AbuseIPDB e IPinfo entram sempre: nao tem interruptor na aba de dominio")

root.destroy()
encerrar()
