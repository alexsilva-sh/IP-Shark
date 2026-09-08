"""O que a varredura deixou de pagar: X-Force recusado, pool ocioso e fontes em serie.

Nenhum Chrome e iniciado e nenhuma requisicao sai daqui -- as fontes sao substituidas por
funcoes que so registram quando foram chamadas.
"""
import threading
import time
import tkinter as tk
from tkinter import ttk

from _comum import bloquear_rede, check, encerrar

import app as gui
from core import api as core
from ui import aba_ip, navegadores, tema
from ui import fontes as catalogo

bloquear_rede(core)
gui.IPCheckerApp._init_drivers_async = lambda self, count=3: None


print("\n[1] A folga de requisicoes e repartida entre lista e fontes")
check(core.largura_por_indicador(1) == core.LIMITE_REQUISICOES,
      "um indicador sozinho usa a folga inteira")
check(core.largura_por_indicador(5) == 2, "cinco indicadores dividem a folga")
check(core.largura_por_indicador(50) == 1,
      "lista longa volta a consultar em serie, em vez de multiplicar os paralelismos")
check(core.largura_por_indicador(0) == core.LIMITE_REQUISICOES,
      "lista vazia nao divide por zero")


print("\n[2] em_paralelo devolve o mesmo que a chamada em serie")
tarefas = {"a": lambda: ("A", 1), "b": lambda: ("B", 2), "c": lambda: ("C", 3)}
check(core.em_paralelo(tarefas, 1) == {"a": ("A", 1), "b": ("B", 2), "c": ("C", 3)},
      "em serie, cada chave traz o seu retorno")
check(core.em_paralelo(tarefas, 4) == core.em_paralelo(tarefas, 1),
      "e em paralelo o resultado e identico")
check(list(core.em_paralelo(tarefas, 4)) == ["a", "b", "c"],
      "a ordem de insercao sobrevive: as colunas seguem a mesma sequencia de sempre")


def _estoura():
    raise RuntimeError("fonte quebrada")


try:
    core.em_paralelo({"a": _estoura, "b": lambda: 1}, 4)
    quebrou = False
except RuntimeError:
    quebrou = True
check(quebrou, "excecao de uma fonte sobe como subiria em serie, em vez de sumir")

lentas = {chave: (lambda: time.sleep(0.3)) for chave in "abcd"}
inicio = time.monotonic()
core.em_paralelo(lentas, 4)
juntas = time.monotonic() - inicio
check(juntas < 0.3 * 4 * 0.6,
      f"quatro fontes de 0,30s levam menos que a soma ({juntas:.2f}s)")


print("\n[3] As fontes de um mesmo IP vao juntas quando a lista e curta")
root = tk.Tk()
tema.configurar_estilos(ttk.Style())
root.withdraw()
app = gui.IPCheckerApp(root)

pico = {"maximo": 0, "atual": 0}
trava = threading.Lock()


def _fonte_lenta(retorno):
    def _consulta(_alvo):
        with trava:
            pico["atual"] += 1
            pico["maximo"] = max(pico["maximo"], pico["atual"])
        time.sleep(0.2)
        with trava:
            pico["atual"] -= 1
        return retorno
    return _consulta


aba_ip.check_ip_abuseipdb = _fonte_lenta(({"data": {}}, core.FONTE_OK))
aba_ip.check_ip_virustotal = _fonte_lenta((None, core.FONTE_SEM_DADOS))
aba_ip.check_ip_metadefender = _fonte_lenta((None, core.FONTE_SEM_DADOS))
aba_ip.get_location = _fonte_lenta(("-", "-"))

app.fontes_ip_varredura = catalogo.padrao("ip")
app.largura_fontes_ip = core.largura_por_indicador(1)
inicio = time.monotonic()
app._consultar_ip(1, "8.8.8.8", 1)
com_folga = time.monotonic() - inicio
check(pico["maximo"] > 1, f"as fontes do IP foram consultadas ao mesmo tempo ({pico['maximo']})")
check(com_folga < 0.2 * 4 * 0.7, f"e a espera caiu para perto da mais lenta ({com_folga:.2f}s)")

pico["maximo"] = 0
app.largura_fontes_ip = core.largura_por_indicador(50)
app._consultar_ip(1, "8.8.8.8", 50)
check(pico["maximo"] == 1,
      "numa lista de cinquenta, cada IP volta a consultar em serie")


print("\n[4] O X-Force so e cobrado uma vez por sessao quando o portal recusa")
consultas = []


def _portal_pede_login(_driver, alvo):
    consultas.append(alvo)
    return "login"


class PoolFalso:
    def __init__(self):
        self.emprestimos = 0

    class _Emprestimo:
        def __init__(self, pool):
            self.pool = pool

        def __enter__(self):
            self.pool.emprestimos += 1
            return object()

        def __exit__(self, *_):
            return False

    def emprestar(self):
        return self._Emprestimo(self)


app.driver_pool = PoolFalso()
app.xforce_pediu_login = False

score, estado = app._consultar_ibm(_portal_pede_login, "8.8.8.8")
check(estado == core.FONTE_SEM_SESSAO, "a primeira recusa vira FONTE_SEM_SESSAO")
check(app.xforce_pediu_login, "e o disjuntor fica armado")

for alvo in ("1.1.1.1", "9.9.9.9", "8.8.4.4"):
    _score, estado = app._consultar_ibm(_portal_pede_login, alvo)
    check(estado == core.FONTE_SEM_SESSAO, f"{alvo} continua saindo como sem sessao")

check(len(consultas) == 1,
      f"mas o portal so foi visitado uma vez ({len(consultas)}): os 18 s de espera nao se repetem")
check(app.driver_pool.emprestimos == 1, "e o pool nao foi ocupado de novo")


print("\n[5] O pool de navegadores so sobe quando alguem precisa dele")
navegadores.start_browser = lambda: (_ for _ in ()).throw(
    AssertionError("navegador nao devia subir sem fonte de navegador ligada"))
pool = navegadores.DriverPool(tamanho=2)
check(pool._boot_pedido is False, "recem-criado, o pool nao pediu boot nenhum")

subidas = []
navegadores.start_browser = lambda: subidas.append(1) or type(
    "D", (), {"window_handles": ["j"], "quit": lambda self: None})()
pool.iniciar_async()
pool.iniciar_async()
pool.boot_concluido.wait(10)
check(len(subidas) == 2, f"o boot roda uma vez so, mesmo pedido duas ({len(subidas)} navegadores)")
pool.encerrar()

check(catalogo.usa_navegador("ip", catalogo.padrao("ip")) is False,
      "a aba de IP no padrao nao precisa de navegador")
check(catalogo.usa_navegador("hash", catalogo.padrao("hash")) is True,
      "a de hash precisa, por causa do JoeSandbox")
check(catalogo.usa_navegador("ip", catalogo.todas("ip")) is True,
      "e volta a precisar se o analista ligar o X-Force")

encerrar()
