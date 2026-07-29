"""Traducao de um resultado do nucleo para o que aparece na tela e na planilha."""
import ipaddress
import re

from core import api
from core.reputacao import is_valid_ip
from i18n import t

VERDICT_KEYS = {
    "clean": "verdict_clean",
    "whitelisted": "verdict_whitelisted",
    "whitelisted_bad": "verdict_review",
    "bad": "verdict_bad",
    "incompleto": "verdict_incomplete",
    "unknown": "verdict_unknown",
}

VERDICT_TAGS = {
    "clean": "clean",
    "whitelisted": "clean",
    "whitelisted_bad": "review",
    "bad": "bad",
    "incompleto": "review",
    "unknown": "unknown",
}

ESTADO_TEXTO = {
    api.FONTE_SEM_CHAVE: "source_no_key",
    api.FONTE_COTA: "source_quota",
    api.FONTE_INDISPONIVEL: "source_unavailable",
    api.FONTE_SEM_DADOS: "source_no_data",
}

FONTES_NOMES = {"abuse": "AbuseIPDB", "vt": "VirusTotal",
                "ibm": "IBM X-Force", "alien": "AlienVault"}


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
    return f"{len(itens)} {t('count_items')}" if itens else ""


def _cabecalho(indicador, rotulo, index, total):
    return f"[{indicador}] - {rotulo}" if total == 1 else f"[{index}] {indicador} - {rotulo}"


def relatorio_ip(data, index=None, total=1):
    rotulos = {
        "clean": t("reputation_clean"),
        "bad": t("reputation_bad"),
        "whitelisted": f"{t('reputation_clean')} ({t('whitelisted')})",
        "whitelisted_bad": t("reputation_whitelisted_bad"),
        "incompleto": t("verdict_incomplete"),
    }
    estados = data.get("estados", {})
    linhas = [_cabecalho(data["ip"], rotulos[data["status"]], index, total)]
    if data.get("fontes_indisponiveis"):
        linhas.append(t("sources_incomplete").format(fontes=", ".join(data["fontes_indisponiveis"])))
    linhas.append(f"{t('abuseipdb_score')}: {texto_fonte(data['abuse_score'], estados.get('abuse'), '%')}")
    linhas.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if data["ibm_score"] or estados.get("ibm") in api.ESTADOS_SEM_RESPOSTA:
        linhas.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    linhas.append(f"{t('domain_label')}: {data['domain']}")
    linhas.append(f"{t('country_city_label')}: {data['country']}, {data['city']}")
    linhas.append(f"{t('last_report_label')}: {data['last_report'] or t('no_records')}")
    linhas.append(f"- {data['links']['abuse']}")
    linhas.append(f"- {data['links']['vt']}")
    if data["links"].get("ibm"):
        linhas.append(f"- {data['links']['ibm']}")
    return "\n".join(linhas)


def linha_planilha_ip(data, com_ibm):
    estados = data.get("estados", {})
    linha = [data["ip"], t(VERDICT_KEYS[data["status"]]),
             texto_fonte(data["abuse_score"], estados.get("abuse"), "%"),
             texto_fonte(data["vt_score"], estados.get("vt"))]
    if com_ibm:
        linha.append(texto_fonte(data["ibm_score"] or "", estados.get("ibm")))
    linha += [data["domain"], data["country"], data["city"],
              data["last_report"] or t("no_reports"),
              data["links"]["abuse"], data["links"]["vt"]]
    if com_ibm:
        linha.append(data["links"]["ibm"] or "")
    return linha


def colunas_ip(data, ultima):
    estados = data.get("estados", {})
    return (data["ip"], t(VERDICT_KEYS[data["status"]]),
            coluna_fonte(data["abuse_score"], estados.get("abuse"), "%"),
            coluna_fonte(data["vt_score"], estados.get("vt")),
            coluna_fonte(data["ibm_score"] or "-", estados.get("ibm")),
            ultima)


def nome_do_arquivo(data):
    """Nome que o VirusTotal deu ao arquivo; '-' quando ele nem conhece o hash."""
    if data["nome_arquivo"]:
        return data["nome_arquivo"]
    return t("unknown") if data["estados"].get("vt") == api.FONTE_OK else "-"


def relatorio_hash(data, com_ibm=True, index=None, total=1):
    estados = data["estados"]
    rotulo = {"bad": t("reputation_bad"), "incompleto": t("verdict_incomplete")}.get(
        data["status"], t("reputation_clean") if data["vt_score"] is not None else t("no_records"))
    cabecalho = _cabecalho(data["hash"], rotulo, index, total)
    if data["joe_found"]:
        cabecalho += f" - {t('joesandbox_found')}"

    linhas = [cabecalho]
    if data["fontes_indisponiveis"]:
        linhas.append(t("sources_incomplete").format(fontes=", ".join(data["fontes_indisponiveis"])))
    linhas.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if com_ibm:
        linhas.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    linhas.append(f"{t('alien_score')}: {texto_fonte(data['alien_score'], estados.get('alien'))}")
    linhas.append(f"{t('file_name')}: {nome_do_arquivo(data)}")
    linhas.append(f"{t('last_analysis_vt')}: {data['ultima_analise'] or 'N/A'}")
    linhas.append(f"- {data['links']['vt']}")
    if com_ibm:
        linhas.append(f"- {data['links']['ibm']}")
    linhas.append(f"- {data['links']['alien']}")
    if data["joe_found"]:
        linhas.append(f"- {data['links']['joe']}")
    return "\n".join(linhas) + "\n"


def linha_planilha_hash(data, com_ibm):
    estados = data["estados"]
    linha = [data["hash"], t(VERDICT_KEYS[data["status"]]),
             texto_fonte(data["vt_score"], estados.get("vt"))]
    if com_ibm:
        linha.append(texto_fonte(data["ibm_score"], estados.get("ibm")))
    linha += [texto_fonte(data["alien_score"], estados.get("alien")),
              nome_do_arquivo(data), data["ultima_analise"] or "N/A", data["links"]["vt"]]
    if com_ibm:
        linha.append(data["links"]["ibm"])
    linha += [data["links"]["alien"], data["links"]["joe"]]
    return linha


def colunas_hash(data, com_ibm):
    estados = data["estados"]
    return (data["hash"], t(VERDICT_KEYS[data["status"]]),
            coluna_fonte(data["vt_score"], estados.get("vt")),
            coluna_fonte(data["ibm_score"], estados.get("ibm")) if com_ibm else "-",
            coluna_fonte(data["alien_score"], estados.get("alien")),
            nome_do_arquivo(data))


def relatorio_url(data, com_ibm=True, index=None, total=1):
    estados = data["estados"]
    rotulo = {"bad": t("reputation_bad"), "incompleto": t("verdict_incomplete")}.get(
        data["status"], t("reputation_clean"))

    linhas = [_cabecalho(data["url"], rotulo, index, total)]
    if data["fontes_indisponiveis"]:
        linhas.append(t("sources_incomplete").format(fontes=", ".join(data["fontes_indisponiveis"])))
    linhas.append(f"{t('vt_score')}: {texto_fonte(data['vt_score'], estados.get('vt'))}")
    if com_ibm:
        linhas.append(f"{t('ibm_score')}: {texto_fonte(data['ibm_score'], estados.get('ibm'))}")
    linhas.append(f"{t('alien_score')}: {texto_fonte(data['alien_score'], estados.get('alien'))}")
    linhas.append(f"- {data['links']['vt']}")
    if com_ibm:
        linhas.append(f"- {data['links']['ibm']}")
    linhas.append(f"- {data['links']['alien']}")
    return "\n".join(linhas)


def linha_planilha_url(data, com_ibm):
    estados = data["estados"]
    linha = [data["url"], t(VERDICT_KEYS[data["status"]]),
             texto_fonte(data["vt_score"], estados.get("vt"))]
    if com_ibm:
        linha.append(texto_fonte(data["ibm_score"], estados.get("ibm")))
    linha += [texto_fonte(data["alien_score"], estados.get("alien")), data["links"]["vt"]]
    if com_ibm:
        linha.append(data["links"]["ibm"])
    linha.append(data["links"]["alien"])
    return linha


def colunas_url(data, com_ibm):
    estados = data["estados"]
    return (data["url"], t(VERDICT_KEYS[data["status"]]), "-",
            coluna_fonte(data["vt_score"], estados.get("vt")),
            coluna_fonte(data["ibm_score"], estados.get("ibm")) if com_ibm else "-",
            coluna_fonte(data["alien_score"], estados.get("alien")))
