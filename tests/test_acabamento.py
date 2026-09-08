"""Quatro acabamentos: ordem dos IPs, DNS com teto de tempo, versao e escolha guardada.

Sem rede e sem Chrome.
"""
import ipaddress
import socket
import tkinter as tk
from tkinter import ttk
from types import SimpleNamespace

from _comum import bloquear_rede, check, encerrar

import app as gui
import preferencias
from core import api as core
from services import atualizacao
from ui import aba_url, tema
from ui import fontes as catalogo
from ui.widgets import ResultTable

gui.IPCheckerApp._init_drivers_async = lambda self, count=3: None


print("\n[1] A coluna de IP ordena por rede, nao por alfabeto")
ips = ["9.9.9.9", "10.0.0.1", "8.8.8.8", "192.168.1.1", "100.64.0.1"]
ordenados = [valor for _chave, valor in sorted((ResultTable._chave_ordem(v), v) for v in ips)]
check(ordenados == sorted(ips, key=ipaddress.ip_address),
      f"10.0.0.1 deixou de vir antes de 9.9.9.9 ({ordenados})")

misto = ["exemplo.com", "7", "8.8.8.8", "-", "2001:db8::1", "90%"]
saida = [valor for _chave, valor in sorted((ResultTable._chave_ordem(v), v) for v in misto)]
check(saida.index("7") < saida.index("8.8.8.8") < saida.index("exemplo.com"),
      f"placar, depois IP, depois texto ({saida})")
check(saida.index("8.8.8.8") < saida.index("2001:db8::1"),
      "e IPv4 antes de IPv6, em vez de misturados")
check(ResultTable._chave_ordem("90%") < ResultTable._chave_ordem("8.8.8.8"),
      "porcentagem continua sendo lida como numero")


print("\n[2] A resolucao de DNS passa pela camada de rede padronizada")
chamadas = []


def _get(url, **kwargs):
    chamadas.append((url, kwargs.get("params")))
    return SimpleNamespace(
        status_code=200, headers={},
        json=lambda: {"Answer": [{"data": "93.184.216.34"}, {"data": "10.0.0.1"},
                                 {"data": "sem-sentido"}]})


core._sessao = lambda: SimpleNamespace(get=_get)
check(core.resolver_dns("exemplo.com") == ["93.184.216.34", "10.0.0.1", "sem-sentido"],
      "os registros voltam como a API os manda")
check(chamadas[0][0] == core.URL_DNS_GOOGLE and chamadas[0][1]["name"] == "exemplo.com",
      f"pelo endereco do DNS publico, com o dominio em parametro ({chamadas[0]})")

check(aba_url.resolver_via_google_dns("exemplo.com") == ["93.184.216.34"],
      "a aba fica so com o que e IP publico: privado e lixo saem")

core._sessao = lambda: SimpleNamespace(
    get=lambda url, **k: SimpleNamespace(status_code=500, headers={}, json=lambda: {}))
check(core.resolver_dns("exemplo.com") == [], "erro da API vira lista vazia, nao excecao")


print("\n[3] O fallback por socket ganhou teto de tempo")
antes = socket.getdefaulttimeout()
visto = {}


def _lento(dominio):
    visto["timeout"] = socket.getdefaulttimeout()
    raise socket.gaierror("sem resposta")


aba_url.socket.gethostbyname_ex = _lento
check(aba_url.resolver_via_socket("exemplo.com") == [], "falha de resolucao vira lista vazia")
check(visto["timeout"] == aba_url.ESPERA_DNS_SOCKET,
      f"com teto durante a chamada ({visto['timeout']}s), em vez de esperar sem limite")
check(socket.getdefaulttimeout() == antes,
      "e o teto global e devolvido como estava, para nao vazar para o resto do app")


print("\n[4] So versao mais nova vira 'atualizacao disponivel'")
check(atualizacao.e_mais_nova("v4.2", "v4.1") is True, "publicada adiante avisa")
check(atualizacao.e_mais_nova("v4.1", "v4.1") is False, "mesma versao nao avisa")
check(atualizacao.e_mais_nova("v4.0", "v4.1") is False,
      "publicada atras nao avisa -- e o caso de todo build local antes do release")
check(atualizacao.e_mais_nova("v4.10", "v4.9") is True,
      "10 depois de 9: a comparacao e numerica, nao alfabetica")
check(atualizacao.e_mais_nova("v4.1.1", "v4.1") is True, "correcao de terceiro numero avisa")
check(atualizacao.e_mais_nova("", "v4.1") is False, "tag vazia nao avisa")
check(atualizacao.e_mais_nova("v4.1", "") is True, "sem versao local, o publicado vale")


print("\n[5] A escolha de fontes sobrevive ao fechamento do app")
check("fontes" in preferencias.PADRAO, "as preferencias tem lugar para a escolha")
check(catalogo.escolha_salva("ip", {"ip": ["vt", "abuse"]}) == {"vt", "abuse"},
      "a escolha guardada volta como foi salva")
check(catalogo.escolha_salva("ip", {"ip": ["vt", "fonte_que_nao_existe"]}) == {"vt"},
      "fonte que saiu do catalogo entre versoes e ignorada")
check(catalogo.escolha_salva("ip", {"ip": []}) == catalogo.padrao("ip"),
      "escolha vazia cai no padrao: aba sem fonte nenhuma diria 'limpo' sem perguntar a ninguem")
check(catalogo.escolha_salva("ip", {}) == catalogo.padrao("ip"), "sem nada salvo, o padrao")
check(catalogo.escolha_salva("ip", "arquivo estragado") == catalogo.padrao("ip"),
      "e preferencia corrompida tambem cai no padrao")

bloquear_rede(core)
root = tk.Tk()
tema.configurar_estilos(ttk.Style())
root.withdraw()
app = gui.IPCheckerApp(root)

app._aplicar_fontes_ip({"vt", "abuse"})
check(preferencias.carregar()["fontes"]["ip"] == ["abuse", "vt"],
      f"aplicar no modal grava no disco ({preferencias.carregar()['fontes']})")

app._aplicar_fontes_hash({"vt"})
guardadas = preferencias.carregar()["fontes"]
check(guardadas["ip"] == ["abuse", "vt"] and guardadas["hash"] == ["vt"],
      f"e cada aba guarda a sua sem apagar a outra ({guardadas})")

root.destroy()
segundo_root = tk.Tk()
segundo_root.withdraw()
segunda_sessao = gui.IPCheckerApp(segundo_root)
check(segunda_sessao.fontes_ip == {"vt", "abuse"},
      f"na abertura seguinte a escolha volta ({segunda_sessao.fontes_ip})")
check(segunda_sessao.fontes_url == catalogo.padrao("url"),
      "e aba sem escolha salva continua no padrao")

segundo_root.destroy()
encerrar()
