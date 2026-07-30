"""Leitura da busca do JoeSandbox: o que a pagina entrega e o que vira veredito.

O HTML e recorte das paginas reais -- inclusive a legenda no pe, que repete a classe e o
title de todos os icones possiveis e por isso e a armadilha principal do parser.
"""
from _comum import check, encerrar

from core import navegador, reputacao
from i18n import t
from ui import apresentacao
from ui import fontes as catalogo

TODAS = {aba: catalogo.todas(aba) for aba in ("ip", "hash", "url")}
SEM_IBM = {aba: fontes - {"ibm"} for aba, fontes in TODAS.items()}

LEGENDA = """
<div class="clearfix max-size-legend">
  <div class="legend-wrapper">
    <span class="small-legend-title">Windows:</span>
    <span class="legend-entry"><i title="Injects" class="infos-small injects"></i>Injects</span>
    <span class="legend-entry"><i title="Writes Registry keys" class="infos-small writes_registry_keys"></i>Writes Registry keys</span>
    <span class="legend-entry"><i title="Drops PE Files" class="infos-small drops_pe"></i>Drops PE Files</span>
    <span class="legend-entry"><i title="Has more than one Process" class="infos-small more_processes"></i>Has more than one Process</span>
    <span class="legend-entry"><i title="Disassembly is available" class="infos-small has_dis"></i>Disassembly is available</span>
  </div>
  <div class="legend-wrapper">
    <span class="legend-entry"><i title="Generates Internet Traffic" class="infos-small has_traffic"></i> Generates Internet Traffic</span>
    <span class="legend-entry"><i title="Generates HTTP Network Traffic" class="infos-small has_http"></i> Generates HTTP Network Traffic</span>
    <span class="legend-entry"><i title="Creates malicious files" class="infos-small creates_files"></i> Creates malicious files</span>
    <span class="legend-entry"><i title="Contains malware configuration(s)" class="infos-small has_malwareconfig"></i> Contains malware configuration(s)</span>
    <span class="legend-entry"><i title="Live Interaction" class="infos-small vnc_interactive"></i> Live Interaction</span>
  </div>
</div>
"""

# O ID da linha (602255) NAO e o do laudo (350146): o link tem de sair do href.
LINHA_MALICIOSA = """
<tr class="analysis" data-status="finished" data-href="/analysis/602255" data-id="602255">
  <td class="left detection malicious"><div class="wrapper">
    <div class="detection-text"> Malicious </div>
    <div class="right"><ul class="signatures"></ul></div>
    <div class="bottom"><div class="av-detection">AV: 100%</div></div>
  </div></td>
  <td class="left sample-info"><div class="wrapper"><div class="file-name-date">
    <div class="file-name"><span class="clipper" title="ZQY8eUW8bu.dll">ZQY8eUW8bu.dll</span></div>
    <div class="file-date" title="2021-02-08 20:58:09 +01:00">2021-02-08 20:58:09 +01:00
      <div class="architecture" title="Architecture: Windows"><span class="arch-icon-windows"></span></div>
    </div>
  </div></div></td>
  <td class="left download-report"><div class="wrapper">
    <a title="Open Full Report" href="/analysis/350146/0/html" class="report-icon-wrapper"></a>
    <div class="reports-list">
      <a class="open-report" href="/analysis/350146/0/html">Full Report</a>
      <a class="open-report" href="/analysis/350146/0/executive">Management Report</a>
      <a class="open-report" href="/analysis/350146/0/iochtml">IOC Report</a>
    </div>
  </div></td>
  <td class="left class-info"><div class="wrapper">
    <div id="info" class="class-info-element"><div class="class-info-icons">
      <span class="writes_registry_keys infos-small" title="Writes Registry keys"></span>
      <span class="more_processes infos-small" title="Has more than one Process"></span>
      <span class="has_dis infos-small" title="Disassembly is available"></span>
    </div></div>
    <div id="classification" class="class-info-element"><div class="class-info-icons">
      <span class="evad classifications-small" title="Evader"></span>
    </div></div>
  </div></td>
</tr>
"""

# Sem av-detection e sem bloco de classificacao, e com a ordem das classes invertida em
# relacao a linha maliciosa -- as duas variacoes vem das paginas reais.
LINHA_LIMPA = """
<tr class="analysis" data-status="finished" data-href="/analysis/1949917" data-id="1949917">
  <td class="left detection clean"><div class="wrapper">
    <div class="detection-text"> Clean </div>
    <div class="right"><ul class="signatures"></ul></div>
  </div></td>
  <td class="left sample-info"><div class="wrapper"><div class="file-name-date">
    <div class="file-name"><span class="clipper" title="http://www.genreysystems.com">http://www.genreysystems.com</span></div>
    <div class="file-date" title="2026-07-30 05:03:16 +02:00">2026-07-30 05:03:16 +02:00
      <div class="architecture" title="Architecture: Windows"><span class="arch-icon-windows"></span></div>
    </div>
  </div></div></td>
  <td class="left download-report"><div class="wrapper"><div class="reports-list">
    <a class="open-report" href="/analysis/1949917/0/html">Full Report</a>
    <a class="open-report" href="/analysis/1949917/0/executive">Management Report</a>
    <a class="open-report" href="/analysis/1949917/0/iochtml">IOC Report</a>
  </div></div></td>
  <td class="left class-info"><div class="wrapper">
    <div id="info" class="class-info-element"><div class="class-info-icons">
      <span class="infos-small more_processes" title="Has more than one Process"></span>
      <span class="infos-small has_traffic" title="Generates Internet Traffic"></span>
      <span class="infos-small has_http" title="Generates HTTP Network Traffic"></span>
    </div></div>
  </div></td>
</tr>
"""

LINHA_SUSPEITA = """
<tr class="analysis" data-status="finished" data-href="/analysis/700001" data-id="700001">
  <td class="left detection suspicious"><div class="wrapper">
    <div class="detection-text"> Suspicious </div>
  </div></td>
  <td class="left sample-info"><div class="wrapper"><div class="file-name-date">
    <div class="file-name"><span class="clipper" title="setup.exe">setup.exe</span></div>
    <div class="file-date" title="2024-01-01 10:00:00 +01:00">2024-01-01 10:00:00 +01:00</div>
  </div></div></td>
  <td class="left download-report"><div class="wrapper"><div class="reports-list">
    <a class="open-report" href="/analysis/700001/0/html">Full Report</a>
  </div></div></td>
  <td class="left class-info"><div class="wrapper">
    <div id="info" class="class-info-element"><div class="class-info-icons">
      <span class="infos-small email_headers" title="Has Email attachment"></span>
    </div></div>
  </div></td>
</tr>
"""

# Amostra mais recente que a de 2021, para conferir de qual linha sai o "principal".
LINHA_MALICIOSA_NOVA = LINHA_MALICIOSA.replace(
    '"2021-02-08 20:58:09 +01:00"', '"2025-06-11 08:30:00 +02:00"').replace(
    "350146", "988877").replace(
    '<span class="evad classifications-small" title="Evader"></span>',
    '<span class="troj classifications-small" title="Trojan"></span>'
    '<span class="has_malwareconfig infos-small" title="Contains malware configuration(s)"></span>')


def pagina(*linhas):
    return ('<div class="row"><table id="all_analyses_list" class="table analysis-list">'
            '<thead><tr><th>Detection</th></tr></thead>'
            f'<tbody class="blocksTableViewBody">{"".join(linhas)}</tbody></table></div>'
            f"{LEGENDA}")


print("[1] Busca sem nenhuma analise nao produz fonte")
check(navegador.parse_busca_joesandbox(pagina()) is None,
      "tabela vazia devolve None, nao um dict de fonte 'limpa'")
check(navegador.parse_busca_joesandbox("<html><body>nada</body></html>") is None,
      "pagina sem a tabela tambem devolve None")

print("\n[2] Analise maliciosa: tudo que a linha carrega")
joe = navegador.parse_busca_joesandbox(pagina(LINHA_MALICIOSA))
check(joe["veredito"] == "malicious", f"veredito lido da classe do <td> ({joe['veredito']})")
check(joe["av"] == 100, f"taxa de AV virou numero ({joe['av']})")
check(joe["classes"] == {"evad": "Evader"}, f"classificacao com codigo e rotulo ({joe['classes']})")
check(joe["arquivo"] == "ZQY8eUW8bu.dll", f"nome do arquivo ({joe['arquivo']})")
check(joe["plataforma"] == "Windows", f"plataforma sem o prefixo 'Architecture:' ({joe['plataforma']})")
check(joe["data"] == "08/02/2021 20:58:09",
      f"data no formato do resto do app, nao o ISO da pagina ({joe['data']})")
check(joe["analises"] == 1, "contou uma analise")
check(joe["link_html"] == "https://www.joesandbox.com/analysis/350146/0/html",
      f"link do laudo vem do href (350146), nao do data-id (602255) ({joe['link_html']})")
check(joe["link_ioc"] == "https://www.joesandbox.com/analysis/350146/0/iochtml",
      f"e o relatorio de IOC tambem ({joe['link_ioc']})")

print("\n[3] A legenda do pe da pagina nao vaza para as flags")
check(list(joe["flags"]) == ["writes_registry_keys", "more_processes"],
      f"so as flags da <tr>, e has_dis (recurso do site) fora ({list(joe['flags'])})")
limpa = navegador.parse_busca_joesandbox(pagina(LINHA_LIMPA))
check(set(limpa["flags"]) == {"has_http", "has_traffic", "more_processes"},
      f"a legenda tem injects e drops_pe, a amostra limpa nao ({set(limpa['flags'])})")
check(limpa["veredito"] == "clean" and limpa["av"] is None and limpa["classes"] == {},
      "linha limpa nao inventa AV nem classificacao")
check(list(limpa["flags"]) == ["has_http", "has_traffic", "more_processes"],
      f"ordem de saida e a do parser, nao a do HTML ({list(limpa['flags'])})")

print("\n[4] Varias analises: manda o pior veredito, e o laudo e o da mais recente")
varias = navegador.parse_busca_joesandbox(
    pagina(LINHA_LIMPA, LINHA_MALICIOSA, LINHA_SUSPEITA, LINHA_MALICIOSA_NOVA))
check(varias["veredito"] == "malicious", f"pior veredito vence ({varias['veredito']})")
check(varias["analises"] == 4 and varias["decisivas"] == 2,
      f"4 analises, 2 sustentando o veredito ({varias['analises']}/{varias['decisivas']})")
check(varias["data"] == "11/06/2025 08:30:00",
      f"data da maliciosa mais recente, nao da primeira da tabela ({varias['data']})")
check(varias["link_html"] == "https://www.joesandbox.com/analysis/988877/0/html",
      f"o link acompanha a analise que decidiu ({varias['link_html']})")
check("email_headers" not in varias["flags"],
      "comportamento nao herda o das analises que nao sustentam o veredito")
check(set(varias["classes"]) == {"evad", "troj"},
      f"classificacao soma as decisivas ({set(varias['classes'])})")
check(list(varias["flags"])[0] == "has_malwareconfig",
      f"configuracao de malware sai na frente das outras flags ({list(varias['flags'])})")

print("\n[5] So 'Malicious' agrava o veredito do hash")
VT_LIMPO = {"data": {"attributes": {"last_analysis_stats": {"malicious": 0},
                                    "meaningful_name": "nota.txt",
                                    "last_analysis_date": 1700000000}}}
OTX = {"pulsos": None, "familias": [], "adversarios": [], "legitimo": []}
com_malicioso = reputacao.build_hash_result("a" * 32, VT_LIMPO, "-", OTX, joe)
check(com_malicioso["status"] == "bad",
      "VirusTotal limpo, mas o sandbox executou e acusou -> bad")
com_limpo = reputacao.build_hash_result("a" * 32, VT_LIMPO, "-", OTX, limpa)
check(com_limpo["status"] == "clean", "'Clean' do sandbox nao muda o que as outras disseram")
sem_joe = reputacao.build_hash_result("a" * 32, {}, "-", OTX, None)
check(sem_joe["status"] == "sem_registros" and sem_joe["links"]["joe"] is None,
      "busca vazia nao deixa link nem vira fonte que analisou")
suspeito = navegador.parse_busca_joesandbox(pagina(LINHA_SUSPEITA))
check(reputacao.build_hash_result("a" * 32, VT_LIMPO, "-", OTX, suspeito)["status"] == "clean",
      "'Suspicious' nao basta: quem decide bad e deteccao, nao suspeita")

print("\n[6] O relatorio mostra o bloco, e sem analise nem menciona o JoeSandbox")
texto = apresentacao.relatorio_hash(com_malicioso, SEM_IBM["hash"])
check(t("joe_score") in texto and t("joe_verdict_malicious") in texto,
      "veredito do sandbox aparece no detalhe")
check("AV 100%" in texto and "08/02/2021 20:58:09" in texto, "com a taxa de AV e a data")
check(t("joe_class_evad") not in texto and "Evader" not in texto,
      "classificacao fica so na planilha, fora do relatorio")
check(t("joe_flag_registry") in texto and t("joe_flag_processes") in texto,
      "comportamento observado em portugues")
check("ZQY8eUW8bu.dll" in texto and "nota.txt" in texto,
      "os dois nomes do arquivo, o do VirusTotal e o submetido ao sandbox")
check("/analysis/350146/0/html" in texto and "/analysis/350146/0/iochtml" in texto,
      "os dois links do laudo saem na lista")
check("analysis/search?q=" not in texto, "e o link de busca generico nao volta")

texto_sem = apresentacao.relatorio_hash(sem_joe, SEM_IBM["hash"])
check(t("joe_score") not in texto_sem and "joesandbox" not in texto_sem.lower(),
      "sem analise o JoeSandbox nao aparece de forma alguma")
check(apresentacao.colunas_hash(sem_joe, SEM_IBM["hash"])[-1] == "-",
      "e a coluna da tabela fica vazia em vez de mentir")
check(apresentacao.colunas_hash(com_malicioso, SEM_IBM["hash"])[-1] == t("joe_verdict_malicious"),
      "a coluna traz o veredito quando ha analise")

planilha = apresentacao.linha_planilha_hash(com_malicioso, SEM_IBM["hash"])
check(t("joe_class_evad") in planilha, "a classificacao continua chegando na planilha")
check(t("joe_verdict_malicious") in planilha and
      "https://www.joesandbox.com/analysis/350146/0/html" in planilha,
      "veredito e link do laudo na planilha")
check(all(t("otx_mitre") != celula for celula in planilha) and "T1055" not in str(planilha),
      "tecnica MITRE nao sobrou em lugar nenhum")

print("\n[7] Configuracao de malware ganha destaque proprio")
config = apresentacao.relatorio_hash(
    reputacao.build_hash_result("a" * 32, VT_LIMPO, "-", OTX, varias), SEM_IBM["hash"])
check(t("joe_malwareconfig") in config, "linha propria avisando do C2 identificado")
check(t("joe_flag_malwareconfig") not in config,
      "e nao se repete no meio da lista de comportamento")

encerrar()
