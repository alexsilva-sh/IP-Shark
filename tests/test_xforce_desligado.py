"""O X-Force fechado atras de login: fonte desligada por padrao e estado proprio.

Em 2026 a IBM passou a exigir IBMid no portal, e a sessao nao da para guardar -- ela vive
num cookie de sessao que o proprio X-Force invalida assim que ele aparece em outro
navegador. O que sobra e nao consultar por padrao e, quando o analista ligar a fonte, dizer
o motivo certo em vez de culpar a rede.
"""
from _comum import check, encerrar

from core import api as core
from core import navegador, reputacao
from i18n import t
from ui import apresentacao
from ui import fontes as catalogo

TELA_DE_LOGIN = """
<html><body><h1>IBM&#174; X-Force Exchange</h1>
<label>I agree to the <a>Terms of Service</a></label>
<button>Create IBMid</button><button>Log In</button></body></html>
"""

PAGINA_NORMAL = "<html><body><h1 class='risklevelbar high'>1</h1></body></html>"


class DriverFake:
    def __init__(self, html):
        self.page_source = html


print("\n[1] A fonte sai do padrao, mas continua no catalogo")
for aba in ("ip", "hash", "url"):
    check("ibm" not in catalogo.padrao(aba), f"aba de {aba} abre sem o X-Force marcado")
    check("ibm" in catalogo.todas(aba), f"e o modal da aba de {aba} ainda oferece a fonte")
    check(catalogo.padrao(aba) | {"ibm"} == catalogo.todas(aba),
          f"nenhuma outra fonte da aba de {aba} foi desligada junto")

check("ibm" in catalogo.colunas_ocultas("ip", catalogo.padrao("ip")),
      "e a coluna do X-Force some da tabela enquanto a fonte esta fora")


print("\n[2] A tela de IBMid e reconhecida como login, nao como pagina ilegivel")
check(navegador._exige_login(DriverFake(TELA_DE_LOGIN)) is True, "tela de login detectada")
check(navegador._exige_login(DriverFake(PAGINA_NORMAL)) is False,
      "pagina com placar nao e confundida com login")
check(navegador._exige_login(object()) is False, "driver morto nao estoura a deteccao")


print("\n[3] 'login' e um estado proprio, e nao score zero nem falha de rede")
check(reputacao.classificar_ibm("login") == core.FONTE_SEM_SESSAO,
      "portal fechado vira FONTE_SEM_SESSAO")
check(core.FONTE_SEM_SESSAO in core.ESTADOS_SEM_RESPOSTA,
      "e entra na conta de fontes que nao responderam")
check(reputacao.classificar_ibm("error") == core.FONTE_INDISPONIVEL,
      "falha de leitura segue sendo indisponivel")
check(reputacao.classificar_ibm(None) is None, "fonte desligada nao vira estado nenhum")

texto = apresentacao.texto_fonte(None, core.FONTE_SEM_SESSAO)
check(texto == t("source_no_session") and texto != t("source_unavailable"),
      f"o detalhe explica o login exigido em vez de 'falha na consulta' ({texto})")


print("\n[4] Desligada, a fonte nao deixa mais o veredito incompleto")
sem_ibm = reputacao.build_ip_result(
    "8.8.8.8", None, None, None, "N/A", "N/A", "N/A",
    estado_abuse=core.FONTE_OK, estado_vt=core.FONTE_OK, estado_ibm=None)
check(sem_ibm["fontes_indisponiveis"] == [],
      "X-Force fora da varredura nao conta como fonte que faltou")
check(sem_ibm["status"] != "incompleto", "e o IP nao sai como analise incompleta")

com_ibm = reputacao.build_ip_result(
    "8.8.8.8", None, None, None, "N/A", "N/A", "N/A",
    estado_abuse=core.FONTE_OK, estado_vt=core.FONTE_OK, estado_ibm=core.FONTE_SEM_SESSAO)
check("IBM X-Force" in com_ibm["fontes_indisponiveis"],
      "ligada de proposito, ela volta a ser cobrada no relatorio")
check(com_ibm["status"] == "incompleto", "e o veredito volta a ser incompleto")

encerrar()
