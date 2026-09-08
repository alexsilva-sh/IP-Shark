"""Cofre das chaves de API: cifra, tolera arquivo estragado e migra o api.env antigo.

O cofre e o unico lugar do app que guarda credencial em disco, e roda na inicializacao --
`migrar_se_preciso` mexe em arquivo do usuario antes de a janela abrir. Tudo aqui usa a
pasta temporaria que o `_comum` aponta em LOCALAPPDATA, nunca o cofre real.
"""
import json
import os
import tempfile

from _comum import check, encerrar

from services import cofre

CHAVE_FALSA = "abcdef0123456789abcdef0123456789"


print("\n[1] O que vai para o disco esta cifrado")
caminho = cofre.salvar({"ABUSEIPDB_API_KEY": CHAVE_FALSA})
check(os.path.isfile(caminho), f"o arquivo foi criado ({os.path.basename(caminho)})")

bruto = open(caminho, "rb").read()
if cofre.criptografia_disponivel():
    check(CHAVE_FALSA.encode() not in bruto,
          "a chave nao aparece em texto claro: quem abrir o arquivo nao a le")
    check(b"ABUSEIPDB_API_KEY" not in bruto, "nem o nome do campo vaza")
else:
    check(True, "sem DPAPI nesta plataforma; o teste de cifra nao se aplica")

check(cofre.carregar() == {"ABUSEIPDB_API_KEY": CHAVE_FALSA}, "e a leitura devolve o original")


print("\n[2] Salvar uma chave nao derruba as outras nem guarda campo vazio")
cofre.salvar({"ABUSEIPDB_API_KEY": CHAVE_FALSA, "VIRUSTOTAL_API_KEY": "vt-123",
              "IPINFO_API_KEY": "   ", "ALIENVAULT_API_KEY": None})
salvas = cofre.carregar()
check(sorted(salvas) == ["ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY"],
      f"so as preenchidas foram guardadas ({sorted(salvas)})")
check(salvas["VIRUSTOTAL_API_KEY"] == "vt-123", "e o valor chega inteiro")

cofre.salvar({"ABUSEIPDB_API_KEY": f"  {CHAVE_FALSA}  "})
check(cofre.carregar()["ABUSEIPDB_API_KEY"] == CHAVE_FALSA,
      "espaco colado junto com a chave e aparado, em vez de ir para o cabecalho HTTP")


print("\n[3] Cofre estragado nao impede o app de abrir")
with open(cofre.caminho_store(), "wb") as arquivo:
    arquivo.write(b"isto nao e um blob da DPAPI")
check(cofre.carregar() == {}, "arquivo ilegivel vira 'sem chaves', nao excecao")

with open(cofre.caminho_store(), "wb") as arquivo:
    arquivo.write(cofre.cifrar(b'["lista", "onde", "devia", "ser", "objeto"]')
                  if cofre.criptografia_disponivel()
                  else b'["lista", "onde", "devia", "ser", "objeto"]')
check(cofre.carregar() == {}, "JSON valido mas do tipo errado tambem cai no vazio")

cofre.apagar()
check(cofre.carregar() == {}, "e sem arquivo nenhum a leitura segue vazia")
check(cofre.apagar() is False, "apagar o que nao existe devolve False em vez de estourar")


print("\n[4] A gravacao nao deixa o cofre pela metade")
cofre.salvar({"ABUSEIPDB_API_KEY": CHAVE_FALSA})
sobras = [n for n in os.listdir(cofre.pasta_dados()) if n.endswith(".tmp")]
check(sobras == [], f"o arquivo temporario da troca atomica nao ficou para tras ({sobras})")


print("\n[5] Ida e volta pela DPAPI")
if cofre.criptografia_disponivel():
    segredo = "chave com acento: ção e simbolo ✓".encode("utf-8")
    check(cofre.decifrar(cofre.cifrar(segredo)) == segredo,
          "cifrar e decifrar devolve os mesmos bytes, acentos incluidos")
    estourou = False
    try:
        cofre.decifrar(b"lixo que nao veio da DPAPI")
    except Exception:
        estourou = True
    check(estourou, "e blob invalido levanta, para o carregar() poder tratar")
else:
    check(True, "sem DPAPI nesta plataforma")


print("\n[6] O api.env legado e importado uma vez so")
base = tempfile.mkdtemp(prefix="ipshark-teste-apienv-")
os.makedirs(os.path.join(base, "config"), exist_ok=True)
antigo = os.path.join(base, "config", "api.env")
with open(antigo, "w", encoding="utf-8") as arquivo:
    arquivo.write("# comentario ignorado\n"
                  "ABUSEIPDB_API_KEY=\"chave-antiga\"\n"
                  "VIRUSTOTAL_API_KEY='vt-antiga'\n"
                  "LINHA_SEM_IGUAL\n"
                  "CHAVE_DESCONHECIDA=nao-deve-entrar\n"
                  "IPINFO_API_KEY=\n")

cofre.apagar()
check(cofre.localizar_api_env(base) == os.path.abspath(antigo), "o api.env e localizado")
check(cofre.migrar_se_preciso(base) is True, "e migrado quando ainda nao ha cofre")

migradas = cofre.carregar()
check(migradas == {"ABUSEIPDB_API_KEY": "chave-antiga", "VIRUSTOTAL_API_KEY": "vt-antiga"},
      f"aspas caem, campo vazio e chave desconhecida ficam de fora ({sorted(migradas)})")
check(os.path.exists(antigo), "o arquivo antigo continua no lugar: apagar e decisao do usuario")

check(cofre.migrar_se_preciso(base) is False,
      "com cofre ja existente a migracao nao roda de novo")
cofre.salvar({"ABUSEIPDB_API_KEY": "chave-nova"})
cofre.migrar_se_preciso(base)
check(cofre.carregar()["ABUSEIPDB_API_KEY"] == "chave-nova",
      "e por isso a chave antiga nao volta por cima da que o usuario cadastrou")

cofre.apagar()
check(cofre.migrar_se_preciso(tempfile.mkdtemp()) is False,
      "sem api.env nenhum, a migracao apenas nao acontece")

vazio = tempfile.mkdtemp(prefix="ipshark-teste-vazio-")
os.makedirs(os.path.join(vazio, "config"), exist_ok=True)
with open(os.path.join(vazio, "config", "api.env"), "w", encoding="utf-8") as arquivo:
    arquivo.write("SO_LIXO=1\n")
check(cofre.migrar_se_preciso(vazio) is False,
      "api.env sem nenhuma chave conhecida nao cria cofre vazio")
check(not os.path.exists(cofre.caminho_store()), "e o arquivo do cofre nem chega a existir")


print("\n[7] O catalogo de chaves e o que a tela de configuracao promete")
check(len(cofre.CHAVES) == len({nome for nome, _, _ in cofre.CHAVES}),
      "nenhum nome de chave repetido no catalogo")
for nome, rotulo, link in cofre.CHAVES:
    # O X-Force autentica com par chave/senha, entao nem todo campo termina em _API_KEY.
    check(nome.startswith(nome.split("_")[0]) and "_API_" in nome
          and rotulo and link.startswith("https://"),
          f"{rotulo}: nome, rotulo e link de cadastro presentes")

pares = {nome for nome, _, _ in cofre.CHAVES}
check(("XFORCE_API_KEY" in pares) == ("XFORCE_API_PASSWORD" in pares),
      "chave e senha do X-Force andam juntas no catalogo: metade do par nao autentica")

encerrar()
