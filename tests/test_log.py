"""Registro em arquivo: nivel, rotacao, e o que NAO pode ser gravado.

O arquivo fica em disco por dias, entao a regra mais importante testada aqui e a de
privacidade: indicador de cliente nao entra no registro.
"""
import os
import re
import shutil
import tempfile

from _comum import RAIZ, check, encerrar

# Precisa vir antes de qualquer import que chame log.obter(): a pasta e resolvida na
# primeira configuracao, e dai em diante o handler ja esta preso ao arquivo.
saida = tempfile.mkdtemp(prefix="ipshark-log-")
os.environ["LOCALAPPDATA"] = saida

import log  # noqa: E402

print("\n[1] O registro vai para arquivo, dentro da pasta do app")
registrador = log.obter("teste")
check(log.pasta_dados().startswith(saida), f"pasta segue LOCALAPPDATA ({log.pasta_dados()})")
check(log.caminho_log().endswith("ipshark.log"), "nome do arquivo definido")
registrador.warning("mensagem de teste")
check(os.path.exists(log.caminho_log()), "arquivo de registro criado")
conteudo = open(log.caminho_log(), encoding="utf-8").read()
check("mensagem de teste" in conteudo, "a mensagem chegou ao arquivo")
check("WARNING" in conteudo and "ipshark.teste" in conteudo,
      "linha traz nivel e origem")

print("\n[2] Nivel sai do ambiente, com padrao seguro")
import logging  # noqa: E402
check(logging.getLogger("ipshark").level == logging.INFO, "padrao e INFO")
check(not logging.getLogger("ipshark").propagate,
      "nao propaga para a raiz: evita duplicar em quem embutir o app")
check("DEBUG" in log.NIVEIS and "CRITICAL" in log.NIVEIS, "niveis aceitos declarados")
registrador.debug("nao deve aparecer")
check("nao deve aparecer" not in open(log.caminho_log(), encoding="utf-8").read(),
      "DEBUG nao entra no padrao INFO")

print("\n[3] O registro nao cresce sem limite")
check(log.LIMITE_BYTES <= 1024 * 1024 and log.BACKUPS >= 1,
      f"rotacao limitada (~{log.LIMITE_BYTES * (log.BACKUPS + 1) // 1024} KB no total)")
manipulador = logging.getLogger("ipshark").handlers[0]
check(manipulador.maxBytes == log.LIMITE_BYTES and manipulador.backupCount == log.BACKUPS,
      "o handler realmente aplica a rotacao")

print("\n[4] print() nao volta ao codigo -- num .exe console=False ele some")
sobraram = []
for pasta, _dirs, arquivos in os.walk(os.path.join(RAIZ, "src")):
    if "__pycache__" in pasta:
        continue
    for nome in arquivos:
        if not nome.endswith(".py"):
            continue
        caminho = os.path.join(pasta, nome)
        for numero, linha in enumerate(open(caminho, encoding="utf-8"), 1):
            if re.match(r"\s*print\(", linha):
                sobraram.append(f"{nome}:{numero}")
check(not sobraram, f"nenhum print() em src/ ({sobraram or 'limpo'})")

print("\n[5] PRIVACIDADE: indicador de cliente nao entra no registro")
from types import SimpleNamespace  # noqa: E402

from selenium.common.exceptions import NoSuchElementException  # noqa: E402

from core import navegador  # noqa: E402

navegador.ESPERA_PAGINA = 0.3
navegador.PISO_XFORCE_IP = 0


class DriverMudo:
    """Falha em tudo, para exercitar os caminhos de erro que agora registram."""

    def __init__(self):
        self.window_handles = ["a", "b"]
        self.switch_to = SimpleNamespace(window=lambda _h: None)
        self.page_source = "<body></body>"

    def execute_script(self, *_a):
        pass

    def find_element(self, _by, valor):
        raise NoSuchElementException(valor)

    def close(self):
        self.window_handles = ["a"]


IP_SIGILOSO = "203.0.113.77"
HASH_SIGILOSO = "b" * 32
antes = os.path.getsize(log.caminho_log())
navegador.check_ip_ibm(DriverMudo(), IP_SIGILOSO)
navegador.check_hash_joesandbox(DriverMudo(), HASH_SIGILOSO)
novo = open(log.caminho_log(), encoding="utf-8").read()[antes:]

check(novo.strip(), "os dois erros foram registrados, nao engolidos")
check(IP_SIGILOSO not in novo, "o IP consultado NAO foi para o arquivo")
check(HASH_SIGILOSO not in novo, "o hash consultado NAO foi para o arquivo")
check("X-Force" in novo and "JoeSandbox" in novo, "mas o registro diz qual fonte falhou")

print("\n[6] Preferencias de tela sobrevivem ao fechamento do app")
import json  # noqa: E402

import preferencias  # noqa: E402

check(preferencias.pasta_dados().startswith(saida), "preferencias ficam na pasta do app")
check(preferencias.carregar() == preferencias.PADRAO,
      "sem arquivo, vale o padrao embutido")
check(preferencias.salvar(escala=3, tema="claro"), "gravou")
salvas = preferencias.carregar()
check(salvas["escala"] == 3 and salvas["tema"] == "claro", "leu de volta o que foi gravado")
check(salvas["idioma"] == preferencias.PADRAO["idioma"],
      "salvar uma chave nao apaga as outras")
preferencias.salvar(idioma="en")
check(preferencias.carregar()["escala"] == 3, "a escala sobreviveu ao salvar o idioma")

with open(preferencias.caminho(), "w", encoding="utf-8") as f:
    f.write("{isto nao e json")
check(preferencias.carregar() == preferencias.PADRAO,
      "arquivo corrompido cai no padrao em vez de impedir o app de abrir")
with open(preferencias.caminho(), "w", encoding="utf-8") as f:
    json.dump({"escala": "grande", "tema": 7, "lixo": 1}, f)
check(preferencias.carregar() == preferencias.PADRAO,
      "tipo errado e chave desconhecida sao ignorados")

# Se a pasta nao puder ser criada, o app segue funcionando -- so nao lembra a escolha.
# Um arquivo ocupando o caminho reproduz isso sem depender de permissao do sistema.
obstruido = os.path.join(saida, "obstruido")
with open(obstruido, "w", encoding="utf-8") as f:
    f.write("sou um arquivo, nao uma pasta")
preferencias.pasta_dados = lambda: os.path.join(obstruido, "IPShark")
check(preferencias.salvar(escala=1) is False, "falha ao gravar e reportada, nao levantada")
check(preferencias.carregar() == preferencias.PADRAO, "e a leitura tambem nao estoura")

shutil.rmtree(saida, ignore_errors=True)
encerrar()
