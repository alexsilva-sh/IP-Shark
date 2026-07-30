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
              ("otx_mitre", alien.get("tecnicas"), ", "),
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


def relatorio_ip(data, index=None, total=1):
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
    linhas.append(f"{t('abuseipdb_score')}: {texto_fonte(data['abuse_score'], estados.get('abuse'), '%')}")
    linhas.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if data["ibm_score"] or estados.get("ibm") in api.ESTADOS_SEM_RESPOSTA:
        linhas.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    if estados.get("md"):
        linhas.append(f"{t('md_score')}: {texto_fonte(md_placar(data), estados.get('md'))}")
    linhas.append(f"{t('domain_label')}: {data['domain']}")
    linhas.append(f"{t('country_city_label')}: {data['country']}, {data['city']}")
    linhas.append(f"{t('last_report_label')}: {data['last_report'] or t('no_records')}")
    linhas.append(f"- {data['links']['abuse']}")
    linhas.append(f"- {data['links']['vt']}")
    if data["links"].get("ibm"):
        linhas.append(f"- {data['links']['ibm']}")
    if data["links"].get("md"):
        linhas.append(f"- {data['links']['md']}")
    return "\n".join(linhas)


def linha_planilha_ip(data, com_ibm):
    estados = data.get("estados", {})
    linha = [data["ip"], t(VERDICT_KEYS[data["status"]]),
             texto_fonte(data["abuse_score"], estados.get("abuse"), "%"),
             texto_fonte(data["vt_score"], estados.get("vt"))]
    if com_ibm:
        linha.append(texto_fonte(data["ibm_score"] or "", estados.get("ibm")))
    linha += [texto_fonte(md_placar(data), estados.get("md")),
              data["domain"], data["country"], data["city"],
              data["last_report"] or t("no_reports"),
              data["links"]["abuse"], data["links"]["vt"]]
    if com_ibm:
        linha.append(data["links"]["ibm"] or "")
    linha.append(data["links"].get("md") or "")
    return linha


def colunas_ip(data, ultima):
    estados = data.get("estados", {})
    return (data["ip"], t(VERDICT_KEYS[data["status"]]),
            coluna_fonte(data["abuse_score"], estados.get("abuse"), "%"),
            coluna_fonte(data["vt_score"], estados.get("vt")),
            coluna_fonte(data["ibm_score"] or "-", estados.get("ibm")),
            coluna_fonte(md_placar(data) or "-", estados.get("md")),
            ultima)


def nome_do_arquivo(data):
    """Nome que o VirusTotal deu ao arquivo; '-' quando ele nem conhece o hash."""
    if data["nome_arquivo"]:
        return data["nome_arquivo"]
    return t("unknown") if data["estados"].get("vt") == api.FONTE_OK else "-"


def relatorio_hash(data, com_ibm=True, index=None, total=1):
    estados = data["estados"]
    rotulo = {"bad": t("reputation_bad"), "incompleto": t("verdict_incomplete"),
              "sem_registros": t("no_records")}.get(data["status"], t("reputation_clean"))
    cabecalho = _cabecalho(data["hash"], rotulo, index, total)
    if data["joe_found"]:
        cabecalho += f" - {t('joesandbox_found')}"

    linhas = [cabecalho]
    if data["fontes_indisponiveis"]:
        linhas.append(t("sources_incomplete").format(fontes=", ".join(data["fontes_indisponiveis"])))
    linhas.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if com_ibm:
        linhas.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    linhas.append(linha_alienvault(data, estados.get("alien")))
    linhas += linhas_otx(data)
    if estados.get("md"):
        linhas.append(f"{t('md_score')}: {texto_fonte(md_placar(data), estados.get('md'))}")
    linhas.append(f"{t('file_name')}: {nome_do_arquivo(data)}")
    linhas.append(f"{t('last_analysis_vt')}: {data['ultima_analise'] or 'N/A'}")
    linhas.append(f"- {data['links']['vt']}")
    if com_ibm:
        linhas.append(f"- {data['links']['ibm']}")
    linhas.append(f"- {data['links']['alien']}")
    if data["links"].get("md"):
        linhas.append(f"- {data['links']['md']}")
    if data["joe_found"]:
        linhas.append(f"- {data['links']['joe']}")
    return "\n".join(linhas) + "\n"


def linha_planilha_hash(data, com_ibm):
    estados = data["estados"]
    linha = [data["hash"], t(VERDICT_KEYS[data["status"]]),
             texto_fonte(data["vt_score"], estados.get("vt"))]
    if com_ibm:
        linha.append(texto_fonte(data["ibm_score"], estados.get("ibm")))
    linha += [texto_fonte(alien_placar(data), estados.get("alien")),
              texto_fonte(md_placar(data), estados.get("md")),
              nome_do_arquivo(data), data["ultima_analise"] or "N/A", data["links"]["vt"]]
    if com_ibm:
        linha.append(data["links"]["ibm"])
    linha += [data["links"]["alien"], data["links"].get("md") or "", data["links"]["joe"]]
    return linha


def colunas_hash(data, com_ibm):
    # O nome do arquivo vem logo depois do veredito: e a coluna mais larga e, no fim da
    # linha, era a primeira a sair da tela em janela estreita.
    estados = data["estados"]
    return (data["hash"], t(VERDICT_KEYS[data["status"]]), nome_do_arquivo(data),
            coluna_fonte(data["vt_score"], estados.get("vt")),
            coluna_fonte(data["ibm_score"], estados.get("ibm")) if com_ibm else "-",
            coluna_fonte(alien_coluna(data), estados.get("alien")),
            coluna_fonte(md_placar(data) or "-", estados.get("md")))


def relatorio_url(data, com_ibm=True, index=None, total=1):
    estados = data["estados"]
    rotulo = {"bad": t("reputation_bad"), "incompleto": t("verdict_incomplete"),
              "sem_registros": t("no_records")}.get(data["status"], t("reputation_clean"))

    linhas = [_cabecalho(data["url"], rotulo, index, total)]
    if data["fontes_indisponiveis"]:
        linhas.append(t("sources_incomplete").format(fontes=", ".join(data["fontes_indisponiveis"])))
    linhas.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if com_ibm:
        linhas.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    linhas.append(linha_alienvault(data, estados.get("alien")))
    linhas += linhas_otx(data)
    if estados.get("md"):
        linhas.append(f"{t('md_score')}: {texto_fonte(md_placar(data), estados.get('md'))}")
    linhas.append(f"- {data['links']['vt']}")
    if com_ibm:
        linhas.append(f"- {data['links']['ibm']}")
    linhas.append(f"- {data['links']['alien']}")
    if data["links"].get("md"):
        linhas.append(f"- {data['links']['md']}")
    return "\n".join(linhas)


def linha_planilha_url(data, com_ibm):
    estados = data["estados"]
    linha = [data["url"], t(VERDICT_KEYS[data["status"]]),
             texto_fonte(data["vt_score"], estados.get("vt"))]
    if com_ibm:
        linha.append(texto_fonte(data["ibm_score"], estados.get("ibm")))
    linha += [texto_fonte(alien_placar(data), estados.get("alien")),
              texto_fonte(md_placar(data), estados.get("md")), data["links"]["vt"]]
    if com_ibm:
        linha.append(data["links"]["ibm"])
    linha += [data["links"]["alien"], data["links"].get("md") or ""]
    return linha


def colunas_url(data, com_ibm):
    estados = data["estados"]
    return (data["url"], t(VERDICT_KEYS[data["status"]]), "-",
            coluna_fonte(data["vt_score"], estados.get("vt")),
            coluna_fonte(data["ibm_score"], estados.get("ibm")) if com_ibm else "-",
            coluna_fonte(alien_coluna(data), estados.get("alien")),
            coluna_fonte(md_placar(data) or "-", estados.get("md")))
