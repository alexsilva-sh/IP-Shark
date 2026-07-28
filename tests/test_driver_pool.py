"""Pool de navegadores do X-Force. Nenhum Chrome de verdade e iniciado."""
import time
import tkinter as tk
from tkinter import ttk

from _comum import bloquear_rede, check, encerrar

import ip_checker_gui_dark as gui
import ip_checker_core as core


class DriverFake:
    def __init__(self, atraso=0.0):
        self.atraso = atraso
        self.vivo = True
        self.encerrado = False
        if atraso:
            time.sleep(atraso)

    @property
    def window_handles(self):
        if not self.vivo:
            raise RuntimeError("sessao perdida")
        return ["janela"]

    def quit(self):
        self.encerrado = True


def fabricar(atraso=0.0, falhar_sempre=False, falhar_ate=0):
    """Substitui start_browser. Conta chamadas e simula falhas de inicializacao."""
    estado = {"chamadas": 0, "criados": []}

    def _start():
        estado["chamadas"] += 1
        if falhar_sempre or estado["chamadas"] <= falhar_ate:
            raise RuntimeError("chrome nao encontrado")
        d = DriverFake(atraso)
        estado["criados"].append(d)
        return d

    gui.start_browser = _start
    return estado


print("\n[1] Os 3 navegadores sobem em paralelo, nao em serie")
gui.DriverPool.ESPERA_ENTRE_TENTATIVAS = 0.01
estado = fabricar(atraso=0.4)
pool = gui.DriverPool(tamanho=3)
inicio = time.time()
pool.iniciar_async()
pool.boot_concluido.wait(10)
decorrido = time.time() - inicio
check(pool.vivos == 3, "os 3 navegadores subiram")
check(decorrido < 0.4 * 3 * 0.8, f"boot paralelo ({decorrido:.2f}s para 3x 0.40s em serie)")
pool.encerrar()

print("\n[2] Falha ao iniciar e reportada, nao engolida")
avisos = []
estado = fabricar(falhar_sempre=True)
pool = gui.DriverPool(tamanho=3, ao_degradar=lambda v, t_, e: avisos.append((v, t_, e)))
pool.iniciar_async()
pool.boot_concluido.wait(10)
check(pool.vivos == 0, "nenhum navegador vivo")
check(len(avisos) == 1 and avisos[0][0] == 0, "callback de degradacao disparou com 0 vivos")
check("chrome" in avisos[0][2].lower(), "motivo do erro chegou junto")
check(estado["chamadas"] == 9, f"3 navegadores x 3 tentativas ({estado['chamadas']} chamadas)")

print("\n[3] Pool parcial tambem avisa")
avisos = []
estado = fabricar(falhar_ate=3)   # as 3 primeiras tentativas falham
pool = gui.DriverPool(tamanho=3, ao_degradar=lambda v, t_, e: avisos.append((v, t_, e)))
pool.iniciar_async()
pool.boot_concluido.wait(10)
check(0 < pool.vivos <= 3, f"pool subiu parcial ou completo ({pool.vivos}/3)")
if pool.vivos < 3:
    check(len(avisos) == 1, "avisou degradacao parcial")
else:
    check(len(avisos) == 0, "pool completo nao avisa")
pool.encerrar()

print("\n[4] Sem navegador, emprestar falha rapido em vez de pendurar")
fabricar(falhar_sempre=True)
pool = gui.DriverPool(tamanho=2)
pool.iniciar_async()
pool.boot_concluido.wait(10)
inicio = time.time()
try:
    with pool.emprestar():
        check(False, "nao deveria emprestar")
except gui.DriverIndisponivel as e:
    check(time.time() - inicio < 1, f"falhou em {time.time() - inicio:.2f}s, sem esperar o timeout")
    check(e.vivos == 0, "excecao informa quantos estao vivos")

print("\n[5] Espera do emprestimo tem teto")
fabricar()
pool = gui.DriverPool(tamanho=1)
pool.TIMEOUT_EMPRESTIMO = 0.3
pool.iniciar_async()
pool.boot_concluido.wait(10)
with pool.emprestar():           # segura o unico driver
    inicio = time.time()
    try:
        with pool.emprestar():
            check(False, "nao havia driver livre")
    except gui.DriverIndisponivel:
        check(0.2 < time.time() - inicio < 2, "segundo pedido estourou o timeout em vez de pendurar")
pool.encerrar()

print("\n[6] Navegador morto nao volta para a fila e e reposto")
estado = fabricar()
pool = gui.DriverPool(tamanho=2)
pool.iniciar_async()
pool.boot_concluido.wait(10)
criados_no_boot = estado["chamadas"]
with pool.emprestar() as d:
    d.vivo = False               # simula o Chrome morrendo no meio da consulta
time.sleep(0.5)
check(d.encerrado, "driver morto recebeu quit()")
check(pool.vivos == 2, f"pool voltou ao tamanho ({pool.vivos}/2)")
check(estado["chamadas"] > criados_no_boot, "um substituto foi iniciado")
vivos_na_fila = []
while not pool.fila.empty():
    vivos_na_fila.append(pool.fila.get_nowait())
check(d not in vivos_na_fila, "o morto nao esta na fila")
for x in vivos_na_fila:
    pool.fila.put(x)
pool.encerrar()

print("\n[7] Navegador sadio volta para a fila")
fabricar()
pool = gui.DriverPool(tamanho=1)
pool.iniciar_async()
pool.boot_concluido.wait(10)
with pool.emprestar() as d1:
    pass
with pool.emprestar() as d2:
    pass
check(d1 is d2, "o mesmo driver foi reaproveitado")
check(pool.vivos == 1, "pool nao inchou")

print("\n[8] encerrar() fecha tudo")
estado = fabricar()
pool = gui.DriverPool(tamanho=3)
pool.iniciar_async()
pool.boot_concluido.wait(10)
criados = list(estado["criados"])
pool.encerrar()
check(all(d.encerrado for d in criados), "todos os navegadores receberam quit()")
check(pool.vivos == 0 and pool.fila.empty(), "pool zerado")

print("\n[9] Driver indisponivel vira fonte indisponivel, nao trava a varredura")
root = tk.Tk()
gui.configurar_estilos(ttk.Style())
root.withdraw()
gui.IPCheckerApp._init_drivers_async = lambda self, count=3: None
app = gui.IPCheckerApp(root)
gui.app = app
app.driver_pool.boot_concluido.set()      # boot terminou sem nenhum driver

app.ibm_hash_ativo = True
app.results_hash = []
chamou_ibm = []
gui.check_hash_ibm = lambda d, h: chamou_ibm.append(h)
gui.check_hash_alienvault = lambda h: ("0", "link", core.FONTE_OK)
gui.check_hash_virustotal = lambda h: (None, core.FONTE_INDISPONIVEL)
gui.check_hash_joesandbox = lambda d, h: (False, "link")
bloquear_rede(core)   # se algum mock vazar, a chamada real estoura aqui

inicio = time.time()
texto, status, colunas, estados = app.process_hash("a" * 32, 1)
check(time.time() - inicio < 2, "process_hash retornou em vez de pendurar no pool vazio")
check(not chamou_ibm, "nem tentou usar o X-Force sem driver")
check(estados["ibm"] == core.FONTE_INDISPONIVEL, "X-Force marcado como indisponivel")
check(status == "incompleto", "veredito e incompleto, nao limpo")
check(gui.t("source_unavailable") in texto, "detalhe explica a falha")

print("\n[10] O aviso aparece na janela")
# winfo_ismapped e sempre 0 com a raiz withdrawn; winfo_manager diz se foi empacotado.
check(app.banner.winfo_manager() == "", "banner nao empacotado por padrao")
app.mostrar_aviso(gui.t("drivers_none").format(vivos=0, total=3))
root.update()
check(app.banner.winfo_manager() == "pack", "banner empacotado quando ha aviso")
check("Chrome" in app.banner_label["text"], "aviso diz o que verificar")

root.destroy()
encerrar()
