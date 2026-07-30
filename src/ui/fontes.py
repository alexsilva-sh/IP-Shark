"""Catalogo de fontes por aba: o que o modal oferece e o que as colunas seguem.

Uma fonte desmarcada nao e consultada, e "nao consultada" nao e "indisponivel": chega ao
nucleo como estado None, que fica fora de `fontes_indisponiveis` e de `_sem_registro`. E o
que separa desligar o AbuseIPDB de propósito de ele estar fora do ar.
"""
API, NAVEGADOR = "api", "navegador"

# (chave, rotulo i18n, tipo). As de API vem primeiro para o atalho "so as rapidas" pegar um
# bloco contiguo da lista.
CATALOGO = {
    "ip": (
        ("abuse", "source_abuse", API),
        ("vt", "source_vt", API),
        ("md", "source_md", API),
        ("local", "source_ipinfo", API),
        ("ibm", "source_ibm", NAVEGADOR),
    ),
    "hash": (
        ("vt", "source_vt", API),
        ("alien", "source_alien", API),
        ("md", "source_md", API),
        ("ibm", "source_ibm", NAVEGADOR),
        ("joe", "source_joe", NAVEGADOR),
    ),
    "url": (
        ("vt", "source_vt", API),
        ("alien", "source_alien", API),
        ("md", "source_md", API),
        ("ips", "source_assoc_ips", API),
        ("ibm", "source_ibm", NAVEGADOR),
    ),
}


# Coluna da tabela que cada fonte governa. Na aba de dominio a coluna do AbuseIPDB e dos IPs
# associados: o dominio em si nunca tem placar ali.
COLUNAS = {
    "ip": {"abuse": "abuse", "vt": "vt", "ibm": "ibm", "md": "md", "local": "pais"},
    "hash": {"vt": "vt", "ibm": "ibm", "alien": "alien", "md": "md", "joe": "joe"},
    "url": {"vt": "vt", "ibm": "ibm", "alien": "alien", "md": "md", "ips": "abuse"},
}


def todas(aba):
    return {chave for chave, _rotulo, _tipo in CATALOGO[aba]}


def rapidas(aba):
    return {chave for chave, _rotulo, tipo in CATALOGO[aba] if tipo == API}


def desligadas(aba, ativas):
    return [chave for chave, _rotulo, _tipo in CATALOGO[aba] if chave not in ativas]


def colunas_ocultas(aba, ativas):
    return {COLUNAS[aba][chave] for chave in desligadas(aba, ativas) if chave in COLUNAS[aba]}


def rotulo(aba, chave):
    return next(r for c, r, _tipo in CATALOGO[aba] if c == chave)
