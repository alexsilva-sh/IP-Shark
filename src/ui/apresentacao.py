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


def relatorio_ip(data, index=None, total=1):
    rotulos = {
        "clean": t("reputation_clean"),
        "bad": t("reputation_bad"),
        "whitelisted": f"{t('reputation_clean')} ({t('whitelisted')})",
        "whitelisted_bad": t("reputation_whitelisted_bad"),
        "incompleto": t("verdict_incomplete"),
    }
    cabecalho = (f"[{data['ip']}] - {rotulos[data['status']]}" if total == 1
                 else f"[{index}] {data['ip']} - {rotulos[data['status']]}")
    estados = data.get("estados", {})
    linhas = [cabecalho]
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
    linha = [data["ip"],
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
