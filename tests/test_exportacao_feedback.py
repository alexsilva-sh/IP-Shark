"""Exportacao: nome sem colisao, cancelamento honesto e resposta ao analista.

A planilha e o que o analista entrega ao cliente. Antes o nome era fixo, entao a exportacao
seguinte apagava a anterior na mesma pasta; a falha de gravacao subia para um callback do Tk
e sumia num executavel sem console; e nem o sucesso era confirmado.
"""
import os
import tempfile
import tkinter as tk
from datetime import datetime
from tkinter import ttk

from _comum import check, encerrar

import app as gui
from i18n import t
from services import exportacao
from ui import tema

gui.IPCheckerApp._init_drivers_async = lambda self, count=3: None

CABECALHO = ["IP", "Veredito", "AbuseIPDB"]
LINHA = [["8.8.8.8", "● Limpo", "0%"]]


print("\n[1] O nome carimba data e hora, entao nao colide")
nome = exportacao.nome_com_data("ip_results.xlsx", datetime(2026, 9, 7, 22, 31, 5))
check(nome == "ip_results_20260907-223105.xlsx", f"prefixo e extensao preservados ({nome})")
check(exportacao.nome_com_data("x.xlsx") != exportacao.nome_com_data(
      "x.xlsx", datetime(2020, 1, 1)), "carimbos diferentes dao nomes diferentes")


print("\n[2] Duas exportacoes na mesma pasta convivem")
pasta = tempfile.mkdtemp(prefix="ipshark-teste-export-")
exportacao.escolher_diretorio = lambda parent=None, titulo=None: pasta

primeiro = exportacao.salvar_planilha(LINHA, CABECALHO, filename="ip_results.xlsx")
segundo = exportacao.salvar_planilha([["1.1.1.1", "✖ Malicioso", "90%"]], CABECALHO,
                                     filename="ip_results.xlsx")
check(primeiro != segundo, "a segunda gravacao foi para outro arquivo")
check(os.path.isfile(primeiro) and os.path.isfile(segundo),
      "e as duas planilhas continuam no disco")
check(len(os.listdir(pasta)) == 2, f"nenhuma foi apagada em silencio ({os.listdir(pasta)})")
# Duas gravacoes no mesmo segundo -- dois cliques seguidos -- caem no mesmo carimbo.
terceiro = exportacao.salvar_planilha(LINHA, CABECALHO, filename="ip_results.xlsx")
check(terceiro not in (primeiro, segundo) and os.path.isfile(terceiro),
      f"nem no mesmo segundo uma planilha come a outra ({os.path.basename(terceiro)})")


print("\n[3] Cancelar o seletor de pasta cancela mesmo")
exportacao.escolher_diretorio = lambda parent=None, titulo=None: None
antes = set(os.listdir(pasta))
check(exportacao.salvar_planilha(LINHA, CABECALHO, filename="ip_results.xlsx") is None,
      "nada e gravado quando o analista desiste")
check(set(os.listdir(pasta)) == antes,
      "e o relatorio nao vai parar no diretorio de trabalho, onde ninguem procuraria")

check(exportacao.salvar_planilha_dominios({}, CABECALHO, {}, CABECALHO) is None,
      "a planilha de dominios respeita o cancelamento do mesmo jeito")


print("\n[4] O analista sabe o que aconteceu, deu certo ou nao")
root = tk.Tk()
tema.configurar_estilos(ttk.Style())
root.withdraw()
app = gui.IPCheckerApp(root)

dialogos = []
gui.messagebox.showinfo = lambda titulo, texto, **k: dialogos.append(("info", texto))
gui.messagebox.showerror = lambda titulo, texto, **k: dialogos.append(("erro", texto))

exportacao.escolher_diretorio = lambda parent=None, titulo=None: pasta
caminho = app.exportar_planilha(exportacao.salvar_planilha, results=LINHA,
                                headers=CABECALHO, filename="ip_results.xlsx")
check(len(dialogos) == 1 and dialogos[0][0] == "info", "sucesso e confirmado")
check(caminho and caminho in dialogos[0][1],
      f"e a mensagem diz onde o arquivo ficou ({dialogos[0][1]!r})")

del dialogos[:]
exportacao.escolher_diretorio = lambda parent=None, titulo=None: None
check(app.exportar_planilha(exportacao.salvar_planilha, results=LINHA, headers=CABECALHO,
                            filename="ip_results.xlsx") is None,
      "cancelar devolve None")
check(dialogos == [], "e nao mostra caixa nenhuma: desistir nao e erro")


print("\n[5] Planilha aberta no Excel vira mensagem, nao silencio")


def _permissao_negada(**_kwargs):
    raise PermissionError(13, "Permission denied", "ip_results.xlsx")


del dialogos[:]
check(app.exportar_planilha(_permissao_negada) is None, "a falha nao propaga para o Tk")
check(len(dialogos) == 1 and dialogos[0][0] == "erro",
      f"o analista recebe um erro visivel ({dialogos})")
check("Excel" in dialogos[0][1] or "excel" in dialogos[0][1].lower(),
      "que sugere fechar o arquivo antes de tentar de novo")
check(t("export_error").split("{")[0].strip()[:10] in dialogos[0][1],
      "usando o texto traduzido, nao uma string solta")

root.destroy()
encerrar()
