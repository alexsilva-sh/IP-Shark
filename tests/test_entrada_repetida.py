"""Indicador repetido na entrada vira uma consulta so.

Lista colada de log costuma trazer o mesmo indicador varias vezes, e cada repeticao gastava
a cota de todas as fontes para devolver uma linha identica. Nada aqui vai a rede: a varredura
e interrompida logo apos a montagem da lista.
"""
import tkinter as tk
from tkinter import ttk

from _comum import bloquear_rede, check, encerrar

import app as gui
from core import api as core
from i18n import t
from ui import apresentacao, tema

bloquear_rede(core)
gui.IPCheckerApp._init_drivers_async = lambda self, count=3: None


print("\n[1] sem_repetidos mantem a ordem de quem colou")
check(apresentacao.sem_repetidos(["b", "a", "b", "c", "a"]) == ["b", "a", "c"],
      "primeira aparicao fica, as demais saem")
check(apresentacao.sem_repetidos([]) == [], "lista vazia continua vazia")


print("\n[2] O mesmo IP escrito de formas diferentes conta como um")
check(apresentacao.ip_canonico("2001:0db8::0001") == "2001:db8::1", "IPv6 vira a forma curta")
check(apresentacao.ip_canonico("2001:DB8::1") == "2001:db8::1", "e a caixa nao cria outro IP")
check(apresentacao.ip_canonico("nao-e-ip") == "nao-e-ip",
      "o que nao e IP passa intacto, para a validacao decidir")
# Zero a esquerda o Python recusa desde a 3.9.5, por causa da ambiguidade com octal --
# "08.8.8.8" nao e o mesmo que "8.8.8.8", e vira entrada invalida antes de chegar aqui.
check(apresentacao.ip_canonico("08.8.8.8") == "08.8.8.8",
      "zero a esquerda nao e normalizado: fica para a validacao recusar")


print("\n[3] O contador da entrada avisa quantos eram repetidos")
contagem = apresentacao.contar_ips("8.8.8.8 8.8.8.8 1.1.1.1")
check(f"2 {t('count_valid')}" in contagem, f"conta os unicos, nao as linhas ({contagem})")
check(f"1 {t('count_duplicate')}" in contagem, f"e diz quantos repetiram ({contagem})")
check(t("count_duplicate") not in apresentacao.contar_ips("8.8.8.8 1.1.1.1"),
      "sem repeticao, nada de aviso")

hashes = "d41d8cd98f00b204e9800998ecf8427e D41D8CD98F00B204E9800998ECF8427E"
check(f"1 {t('count_valid')}" in apresentacao.contar_hashes(hashes),
      "hash repetido em maiuscula e o mesmo hash")

dominios = "https://exemplo.com/pagina exemplo.com EXEMPLO.COM"
check(f"1 {t('count_valid')}" in apresentacao.contar_dominios(dominios),
      "e caminho, esquema e caixa nao criam dominios diferentes")


print("\n[4] A varredura de IP consulta cada indicador uma vez")
root = tk.Tk()
tema.configurar_estilos(ttk.Style())
root.withdraw()
app = gui.IPCheckerApp(root)

listas = {}


def _capturar(nome):
    def _thread(self, lista):
        listas[nome] = list(lista)
    return _thread


gui.IPCheckerApp._check_ips_thread = _capturar("ip")
gui.IPCheckerApp._check_hashes_thread = _capturar("hash")
gui.IPCheckerApp._check_urls_thread = _capturar("url")

app.entry.texto.insert("1.0", "8.8.8.8\n1.1.1.1\n8.8.8.8\n08.8.8.8\n9.9.9.9\n1.1.1.1")
app.run_check()
check(listas["ip"] == ["8.8.8.8", "1.1.1.1", "9.9.9.9"],
      f"seis linhas viram tres consultas, na ordem colada ({listas['ip']})")

app.hash_entry.texto.insert(
    "1.0", "d41d8cd98f00b204e9800998ecf8427e D41D8CD98F00B204E9800998ECF8427E "
           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
app.run_hash_check()
check(len(listas["hash"]) == 2, f"hash repetido em outra caixa nao repete a consulta ({listas['hash']})")
check(all(h == h.lower() for h in listas["hash"]), "e a lista sai normalizada em minusculas")

app.url_entry.texto.insert("1.0", "https://exemplo.com/pagina exemplo.com EXEMPLO.COM outro.com")
app.run_url_check()
check(listas["url"] == ["exemplo.com", "outro.com"],
      f"o dominio extraido e que decide a repeticao ({listas['url']})")


print("\n[5] Deduplicar nao esconde entrada invalida")
# A varredura anterior nunca "terminou" -- a thread foi substituida --, e run_check
# recusa comecar outra enquanto scanning_ip estiver de pe.
app.scanning_ip = False
app.entry.texto.delete("1.0", "end")
app.entry.texto.insert("1.0", "8.8.8.8 8.8.8.8 192.168.0.1 nao-e-ip")
app.run_check()
check(listas["ip"] == ["8.8.8.8"], "o publico unico entrou")
check(len(app.ignorados_ip) == 2,
      f"e o privado e o invalido seguem listados como ignorados ({app.ignorados_ip})")
check(any("192.168.0.1" in i for i in app.ignorados_ip)
      and any("nao-e-ip" in i for i in app.ignorados_ip),
      "cada um com o seu motivo, em vez de sumir junto com as repeticoes")

root.destroy()
encerrar()
