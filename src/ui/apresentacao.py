"""Traducao de um resultado do nucleo para o que aparece na tela e na planilha."""
import ipaddress
import re

from core import api
from core.reputacao import dominio_valido, extrair_dominio, is_valid_ip
from i18n import t

VERDICT_KEYS = {
    "clean": "verdict_clean",
    "whitelisted": "verdict_whitelisted",
    "whitelisted_bad": "verdict_review",
    "bad": "verdict_bad",
    "incompleto": "verdict_incomplete",
    "sem_registros": "verdict_no_records",
    "unknown": "verdict_unknown",
}

VERDICT_TAGS = {
    "clean": "clean",
    "whitelisted": "clean",
    "whitelisted_bad": "review",
    "bad": "bad",
    "incompleto": "review",
    "sem_registros": "unknown",
    "unknown": "unknown",
}

ESTADO_TEXTO = {
    api.FONTE_SEM_CHAVE: "source_no_key",
    api.FONTE_COTA: "source_quota",
    api.FONTE_INDISPONIVEL: "source_unavailable",
    api.FONTE_SEM_DADOS: "source_no_data",
}

FONTES_NOMES = {"abuse": "AbuseIPDB", "vt": "VirusTotal", "ibm": "IBM X-Force",
                "alien": "AlienVault", "md": "MetaDefender"}

JOE_VEREDITO_KEYS = {"malicious": "joe_verdict_malicious",
                     "suspicious": "joe_verdict_suspicious",
                     "clean": "joe_verdict_clean"}

# A legenda da busca enumera todas as flags que existem, por isso a lista aqui e fechada.
JOE_FLAG_KEYS = {
    "has_malwareconfig": "joe_flag_malwareconfig",
    "injects": "joe_flag_injects",
    "drops_pe": "joe_flag_drops_pe",
    "creates_files": "joe_flag_creates_files",
    "writes_registry_keys": "joe_flag_registry",
    "has_http": "joe_flag_http",
    "has_traffic": "joe_flag_traffic",
    "more_processes": "joe_flag_processes",
    "email_headers": "joe_flag_email",
    "native_cmd": "joe_flag_native_cmd",
    "sends_sms": "joe_flag_sends_sms",
    "recv_sms": "joe_flag_recv_sms",
    "reboot": "joe_flag_reboot",
    "has_expired": "joe_flag_expired",
}
# A taxonomia de classificacao nao esta documentada na pagina; codigo fora do mapa cai no
# rotulo que o JoeSandbox mandou.
JOE_CLASSE_KEYS = {"evad": "joe_class_evad"}


def alien_pulsos(data):
    pulsos = (data.get("alien") or {}).get("pulsos")
    if pulsos is None:
        return ""
    return f"{pulsos} {t('count_pulse') if pulsos == 1 else t('count_pulses')}"


def alien_placar(data):
    """Familia na frente da contagem, para a celula da planilha."""
    alien = data.get("alien") or {}
    texto = alien_pulsos(data)
    return f"{alien['familias'][0]} · {texto}" if texto and alien.get("familias") else texto


def linha_alienvault(data, estado):
    """'AlienVault: 7 pulsos | Relatado como <relato> (+6)'."""
    texto = texto_fonte(alien_pulsos(data), estado)
    alien = data.get("alien") or {}
    if alien.get("titulo") and estado not in api.ESTADOS_SEM_RESPOSTA:
        outros = (alien.get("pulsos") or 1) - 1
        sufixo = f" (+{outros})" if outros > 0 else ""
        texto += f" | {t('otx_pulses')} {alien['titulo']}{sufixo}"
    return f"{t('alien_score')}: {texto}"


def alien_coluna(data):
    """Na celula cabe uma coisa: a familia, ou a contagem quando nao ha familia."""
    alien = data.get("alien") or {}
    if alien.get("familias"):
        return alien["familias"][0]
    pulsos = alien.get("pulsos")
    return "-" if pulsos is None else str(pulsos)


def linhas_otx(data):
    """Atribuicao do OTX: so sai o campo que a fonte trouxe."""
    alien = data.get("alien") or {}
    campos = (("otx_family", alien.get("familias"), ", "),
              ("otx_adversary", alien.get("adversarios"), ", "),
              ("otx_known_good", alien.get("legitimo"), ", "))
    return [f"{t(chave)}: {separador.join(valores)}"
            for chave, valores, separador in campos if valores]


def md_placar(data):
    """'12/20' do multiscanning; so a contagem quando a fonte nao informa o total."""
    md = data.get("md") or {}
    detectados, total = md.get("detectados"), md.get("total")
    if detectados is None:
        return ""
    return f"{detectados}/{total}" if total else str(detectados)


def _joe_rotulos(itens, mapa):
    """Traduz os codigos que conhecemos; o resto sai com o rotulo do proprio JoeSandbox."""
    return [t(mapa[codigo]) if codigo in mapa else rotulo
            for codigo, rotulo in (itens or {}).items()]


def joe_veredito(data):
    """Vazio quando a busca nao achou analise."""
    chave = JOE_VEREDITO_KEYS.get((data.get("joe") or {}).get("veredito"))
    return t(chave) if chave else ""


def joe_classes(data):
    return _joe_rotulos((data.get("joe") or {}).get("classes"), JOE_CLASSE_KEYS)


def joe_comportamento(data):
    """A flag de configuracao de malware fica fora: sai em linha propria."""
    flags = dict((data.get("joe") or {}).get("flags") or {})
    flags.pop("has_malwareconfig", None)
    return _joe_rotulos(flags, JOE_FLAG_KEYS)


def _joe_contagem(joe):
    """'3 analises' e, se os vereditos divergem, quantas sustentam o exibido."""
    total = joe.get("analises") or 1
    if total == 1:
        return t("joe_count_one").format(n=total)
    texto = t("joe_count_many").format(n=total)
    decisivas = joe.get("decisivas") or 0
    if 0 < decisivas < total:
        texto += f", {t('joe_count_verdict').format(n=decisivas)}"
    return texto


def linhas_joesandbox(data):
    """Lista vazia quando nao ha analise: a fonte nem aparece no relatorio."""
    joe = data.get("joe") or {}
    if not joe:
        return []
    partes = [joe_veredito(data) or t("unknown")]
    if joe.get("av") is not None:
        partes.append(t("joe_av").format(pct=joe["av"]))
    if joe.get("plataforma"):
        partes.append(joe["plataforma"])
    partes.append(_joe_contagem(joe))
    if joe.get("data"):
        partes.append(joe["data"])

    linhas = [f"{t('joe_score')}: {' · '.join(partes)}"]
    if "has_malwareconfig" in (joe.get("flags") or {}):
        linhas.append(t("joe_malwareconfig"))
    comportamento = joe_comportamento(data)
    if comportamento:
        linhas.append(f"{t('joe_behavior')}: {', '.join(comportamento)}")
    return linhas


def texto_fonte(valor, estado, sufixo=""):
    """Score da fonte quando ela respondeu; o motivo da ausencia quando nao."""
    if estado in ESTADO_TEXTO:
        return t(ESTADO_TEXTO[estado])
    return f"{valor}{sufixo}"


def coluna_fonte(valor, estado, sufixo=""):
    """Versao curta para a celula da tabela; o motivo completo fica no detalhe."""
    if estado in api.ESTADOS_SEM_RESPOSTA:
        return "!"
    if estado == api.FONTE_SEM_DADOS:
        return "-"
    return f"{valor}{sufixo}"


# ---------- fontes ativas: relatorio, planilha e tabela seguem o mesmo conjunto ----------

def ativa(fontes, chave):
    """fontes=None significa "todas"; chave None e coluna que nao pertence a fonte alguma."""
    return chave is None or fontes is None or chave in fontes


def _estado(data, chave):
    return (data.get("estados") or {}).get(chave)


def _cabecalhos(spec, fontes):
    return [t(chave) for fonte, chave, _valor in spec if ativa(fontes, fonte)]


def _celulas(spec, data, fontes):
    return [valor(data) for fonte, _chave, valor in spec if ativa(fontes, fonte)]


def _celula(data, chave, fontes, valor, sufixo=""):
    """Celula da tabela na tela: fonte desligada fica '-', igual a que nao tem dado."""
    if not ativa(fontes, chave):
        return "-"
    return coluna_fonte(valor(data), _estado(data, chave), sufixo)


def fontes_em_cota(estados):
    return {FONTES_NOMES.get(chave, chave)
            for chave, estado in (estados or {}).items() if estado == api.FONTE_COTA}


def aviso_de_cota(fontes):
    """Aviso de cota esgotada, com estimativa de retorno quando a API mandou Retry-After."""
    partes = [t("quota_warning").format(fontes=", ".join(sorted(fontes)))]
    for fonte in sorted(fontes):
        segundos = api.espera_de_cota(fonte)
        if not segundos:
            continue
        minutos = round(segundos / 60)
        tempo = f"{round(minutos / 60)} h" if minutos >= 90 else f"{max(1, minutos)} min"
        partes.append(t("quota_retry_after").format(fonte=fonte, tempo=tempo))
    return " ".join(partes)


def dividir_entrada(bruto):
    return [p for p in re.split(r"[\s,;]+", bruto or "") if p]


def contar_ips(bruto):
    validos = invalidos = privados = 0
    for item in dividir_entrada(bruto):
        if not is_valid_ip(item):
            invalidos += 1
        elif ipaddress.ip_address(item).is_private:
            privados += 1
        else:
            validos += 1
    if not (validos or invalidos or privados):
        return ""
    partes = [f"{validos} {t('count_valid')}"]
    if invalidos:
        partes.append(f"{invalidos} {t('count_invalid')}")
    if privados:
        partes.append(f"{privados} {t('count_private')}")
    return " · ".join(partes)


def contar_hashes(bruto):
    itens = dividir_entrada(bruto)
    if not itens:
        return ""
    validos = sum(1 for h in itens if re.fullmatch(r"[a-fA-F0-9]{32,64}", h))
    partes = [f"{validos} {t('count_valid')}"]
    if len(itens) - validos:
        partes.append(f"{len(itens) - validos} {t('count_invalid')}")
    return " · ".join(partes)


def contar_dominios(bruto):
    itens = dividir_entrada(bruto)
    if not itens:
        return ""
    validos = sum(1 for item in itens if dominio_valido(extrair_dominio(item)))
    partes = [f"{validos} {t('count_valid')}"]
    if len(itens) - validos:
        partes.append(f"{len(itens) - validos} {t('count_invalid')}")
    return " · ".join(partes)


def _cabecalho(indicador, rotulo, index, total):
    return f"[{indicador}] - {rotulo}" if total == 1 else f"[{index}] {indicador} - {rotulo}"


def relatorio_ip(data, index=None, total=1, fontes=None):
    rotulos = {
        "clean": t("reputation_clean"),
        "bad": t("reputation_bad"),
        "whitelisted": f"{t('reputation_clean')} ({t('whitelisted')})",
        "whitelisted_bad": t("reputation_whitelisted_bad"),
        "incompleto": t("verdict_incomplete"),
        "sem_registros": t("no_records"),
    }
    estados = data.get("estados", {})
    linhas = [_cabecalho(data["ip"], rotulos[data["status"]], index, total)]
    if data.get("fontes_indisponiveis"):
        linhas.append(t("sources_incomplete").format(fontes=", ".join(data["fontes_indisponiveis"])))
    if ativa(fontes, "abuse"):
        linhas.append(f"{t('abuseipdb_score')}: "
                      f"{texto_fonte(data['abuse_score'], estados.get('abuse'), '%')}")
    if ativa(fontes, "vt"):
        linhas.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if data["ibm_score"] or estados.get("ibm") in api.ESTADOS_SEM_RESPOSTA:
        linhas.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    if estados.get("md"):
        linhas.append(f"{t('md_score')}: {texto_fonte(md_placar(data), estados.get('md'))}")
    if ativa(fontes, "abuse"):
        linhas.append(f"{t('domain_label')}: {data['domain']}")
    if ativa(fontes, "local"):
        linhas.append(f"{t('country_city_label')}: {data['country']}, {data['city']}")
    if ativa(fontes, "abuse"):
        linhas.append(f"{t('last_report_label')}: {data['last_report'] or t('no_records')}")
        linhas.append(f"- {data['links']['abuse']}")
    if ativa(fontes, "vt"):
        linhas.append(f"- {data['links']['vt']}")
    if data["links"].get("ibm"):
        linhas.append(f"- {data['links']['ibm']}")
    if data["links"].get("md"):
        linhas.append(f"- {data['links']['md']}")
    return "\n".join(linhas)


def _spec_planilha_ip():
    """(fonte, chave do cabecalho, valor) na ordem da planilha. fonte None = sempre sai."""
    return (
        (None, "csv_ip", lambda d: d["ip"]),
        (None, "csv_verdict", lambda d: t(VERDICT_KEYS[d["status"]])),
        ("abuse", "csv_abuse_score",
         lambda d: texto_fonte(d["abuse_score"], _estado(d, "abuse"), "%")),
        ("vt", "csv_vt_score", lambda d: texto_fonte(d["vt_score"], _estado(d, "vt"))),
        ("ibm", "csv_ibm_score",
         lambda d: texto_fonte(d["ibm_score"] or "", _estado(d, "ibm"))),
        ("md", "csv_md_score", lambda d: texto_fonte(md_placar(d), _estado(d, "md"))),
        ("abuse", "csv_domain", lambda d: d["domain"]),
        ("local", "csv_country", lambda d: d["country"]),
        ("local", "csv_city", lambda d: d["city"]),
        ("abuse", "csv_last_report", lambda d: d["last_report"] or t("no_reports")),
        ("abuse", "csv_abuse_link", lambda d: d["links"]["abuse"]),
        ("vt", "csv_vt_link", lambda d: d["links"]["vt"]),
        ("ibm", "csv_ibm_link", lambda d: d["links"]["ibm"] or ""),
        ("md", "csv_md_link", lambda d: d["links"].get("md") or ""),
    )


def cabecalho_planilha_ip(fontes):
    return _cabecalhos(_spec_planilha_ip(), fontes)


def linha_planilha_ip(data, fontes):
    return _celulas(_spec_planilha_ip(), data, fontes)


def colunas_ip(data, ultima, fontes=None):
    return (data["ip"], t(VERDICT_KEYS[data["status"]]),
            _celula(data, "abuse", fontes, lambda d: d["abuse_score"], "%"),
            _celula(data, "vt", fontes, lambda d: d["vt_score"]),
            _celula(data, "ibm", fontes, lambda d: d["ibm_score"] or "-"),
            _celula(data, "md", fontes, lambda d: md_placar(d) or "-"),
            ultima)


def nome_do_arquivo(data):
    """Nome que o VirusTotal deu ao arquivo; '-' quando ele nem conhece o hash."""
    if data["nome_arquivo"]:
        return data["nome_arquivo"]
    return t("unknown") if data["estados"].get("vt") == api.FONTE_OK else "-"


def nome_do_arquivo_detalhado(data):
    """Com o nome submetido ao JoeSandbox ao lado, quando difere do que o VirusTotal viu."""
    nome = nome_do_arquivo(data)
    joe = (data.get("joe") or {}).get("arquivo")
    if not joe or joe == data.get("nome_arquivo"):
        return nome
    if nome in ("-", t("unknown")):
        return joe
    return f"{nome} ({t('joe_score')}: {joe})"


def relatorio_hash(data, fontes=None, index=None, total=1):
    estados = data["estados"]
    rotulo = {"bad": t("reputation_bad"), "incompleto": t("verdict_incomplete"),
              "sem_registros": t("no_records")}.get(data["status"], t("reputation_clean"))
    linhas = [_cabecalho(data["hash"], rotulo, index, total)]
    if data["fontes_indisponiveis"]:
        linhas.append(t("sources_incomplete").format(fontes=", ".join(data["fontes_indisponiveis"])))
    if ativa(fontes, "vt"):
        linhas.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if ativa(fontes, "ibm"):
        linhas.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    if ativa(fontes, "alien"):
        linhas.append(linha_alienvault(data, estados.get("alien")))
        linhas += linhas_otx(data)
    if estados.get("md"):
        linhas.append(f"{t('md_score')}: {texto_fonte(md_placar(data), estados.get('md'))}")
    linhas += linhas_joesandbox(data)
    linhas.append(f"{t('file_name')}: {nome_do_arquivo_detalhado(data)}")
    if ativa(fontes, "vt"):
        linhas.append(f"{t('last_analysis_vt')}: {data['ultima_analise'] or 'N/A'}")
        linhas.append(f"- {data['links']['vt']}")
    if ativa(fontes, "ibm"):
        linhas.append(f"- {data['links']['ibm']}")
    if ativa(fontes, "alien"):
        linhas.append(f"- {data['links']['alien']}")
    if data["links"].get("md"):
        linhas.append(f"- {data['links']['md']}")
    joe = data.get("joe") or {}
    linhas += [f"- {link}" for link in (joe.get("link_html"), joe.get("link_ioc")) if link]
    return "\n".join(linhas) + "\n"


def _spec_planilha_hash():
    return (
        (None, "csv_hash", lambda d: d["hash"]),
        (None, "csv_verdict", lambda d: t(VERDICT_KEYS[d["status"]])),
        ("vt", "csv_vt_score", lambda d: texto_fonte(d["vt_score"], _estado(d, "vt"))),
        ("ibm", "csv_ibm_score", lambda d: texto_fonte(d["ibm_score"], _estado(d, "ibm"))),
        ("alien", "csv_alien_score",
         lambda d: texto_fonte(alien_placar(d), _estado(d, "alien"))),
        ("md", "csv_md_score", lambda d: texto_fonte(md_placar(d), _estado(d, "md"))),
        ("joe", "csv_joe_verdict", joe_veredito),
        ("joe", "csv_joe_class", lambda d: ", ".join(joe_classes(d))),
        ("joe", "csv_joe_behavior", lambda d: ", ".join(joe_comportamento(d))),
        (None, "csv_file_name", nome_do_arquivo),
        ("vt", "csv_last_analysis", lambda d: d["ultima_analise"] or "N/A"),
        ("vt", "csv_vt_link", lambda d: d["links"]["vt"]),
        ("ibm", "csv_ibm_link", lambda d: d["links"]["ibm"]),
        ("alien", "csv_alien_link", lambda d: d["links"]["alien"]),
        ("md", "csv_md_link", lambda d: d["links"].get("md") or ""),
        ("joe", "csv_joe_link", lambda d: d["links"].get("joe") or ""),
    )


def cabecalho_planilha_hash(fontes):
    return _cabecalhos(_spec_planilha_hash(), fontes)


def linha_planilha_hash(data, fontes):
    return _celulas(_spec_planilha_hash(), data, fontes)


def colunas_hash(data, fontes=None):
    # O nome do arquivo vem logo depois do veredito: e a coluna mais larga e, no fim da
    # linha, era a primeira a sair da tela em janela estreita.
    return (data["hash"], t(VERDICT_KEYS[data["status"]]), nome_do_arquivo(data),
            _celula(data, "vt", fontes, lambda d: d["vt_score"]),
            _celula(data, "ibm", fontes, lambda d: d["ibm_score"]),
            _celula(data, "alien", fontes, alien_coluna),
            _celula(data, "md", fontes, lambda d: md_placar(d) or "-"),
            (joe_veredito(data) or "-") if ativa(fontes, "joe") else "-")


def relatorio_url(data, fontes=None, index=None, total=1):
    estados = data["estados"]
    rotulo = {"bad": t("reputation_bad"), "incompleto": t("verdict_incomplete"),
              "sem_registros": t("no_records")}.get(data["status"], t("reputation_clean"))

    linhas = [_cabecalho(data["url"], rotulo, index, total)]
    if data["fontes_indisponiveis"]:
        linhas.append(t("sources_incomplete").format(fontes=", ".join(data["fontes_indisponiveis"])))
    if ativa(fontes, "vt"):
        linhas.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if ativa(fontes, "ibm"):
        linhas.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    if ativa(fontes, "alien"):
        linhas.append(linha_alienvault(data, estados.get("alien")))
        linhas += linhas_otx(data)
    if estados.get("md"):
        linhas.append(f"{t('md_score')}: {texto_fonte(md_placar(data), estados.get('md'))}")
    if ativa(fontes, "vt"):
        linhas.append(f"- {data['links']['vt']}")
    if ativa(fontes, "ibm"):
        linhas.append(f"- {data['links']['ibm']}")
    if ativa(fontes, "alien"):
        linhas.append(f"- {data['links']['alien']}")
    if data["links"].get("md"):
        linhas.append(f"- {data['links']['md']}")
    return "\n".join(linhas)


def _spec_planilha_url():
    return (
        (None, "csv_domain", lambda d: d["url"]),
        (None, "csv_verdict", lambda d: t(VERDICT_KEYS[d["status"]])),
        ("vt", "csv_vt_score", lambda d: texto_fonte(d["vt_score"], _estado(d, "vt"))),
        ("ibm", "csv_ibm_score", lambda d: texto_fonte(d["ibm_score"], _estado(d, "ibm"))),
        ("alien", "csv_alien_score",
         lambda d: texto_fonte(alien_placar(d), _estado(d, "alien"))),
        ("md", "csv_md_score", lambda d: texto_fonte(md_placar(d), _estado(d, "md"))),
        ("vt", "csv_vt_link", lambda d: d["links"]["vt"]),
        ("ibm", "csv_ibm_link", lambda d: d["links"]["ibm"]),
        ("alien", "csv_alien_link", lambda d: d["links"]["alien"]),
        ("md", "csv_md_link", lambda d: d["links"].get("md") or ""),
    )


def cabecalho_planilha_url(fontes):
    return _cabecalhos(_spec_planilha_url(), fontes)


def linha_planilha_url(data, fontes):
    return _celulas(_spec_planilha_url(), data, fontes)


def colunas_url(data, fontes=None):
    return (data["url"], t(VERDICT_KEYS[data["status"]]), "-",
            _celula(data, "vt", fontes, lambda d: d["vt_score"]),
            _celula(data, "ibm", fontes, lambda d: d["ibm_score"]),
            _celula(data, "alien", fontes, alien_coluna),
            _celula(data, "md", fontes, lambda d: md_placar(d) or "-"))
