"""Catalogo de fontes por aba: o que o modal oferece e o que as colunas seguem.

Uma fonte desmarcada nao e consultada, e "nao consultada" nao e "indisponivel": chega ao
nucleo como estado None, que fica fora de `fontes_indisponiveis` e de `_sem_registro`. E o
que separa desligar o AbuseIPDB de propósito de ele estar fora do ar.
"""
API, NAVEGADOR, REFERENCIA = "api", "navegador", "referencia"

# (chave, rotulo i18n, tipo). As de API vem primeiro para o atalho "so as rapidas" pegar um
# bloco contiguo da lista; as de referencia ficam por ultimo, fora do atalho.
CATALOGO = {
    "ip": (
        ("abuse", "source_abuse", API),
        ("vt", "source_vt", API),
        ("md", "source_md", API),
        ("local", "source_ipinfo", API),
        ("ibm", "source_ibm", REFERENCIA),
    ),
    "hash": (
        ("vt", "source_vt", API),
        ("alien", "source_alien", API),
        ("md", "source_md", API),
        ("joe", "source_joe", NAVEGADOR),
        ("ibm", "source_ibm", REFERENCIA),
    ),
    "url": (
        ("vt", "source_vt", API),
        ("alien", "source_alien", API),
        ("md", "source_md", API),
        ("ips", "source_assoc_ips", API),
        ("ibm", "source_ibm", REFERENCIA),
    ),
}


# Colunas da tabela que cada fonte governa. Na aba de dominio a coluna do AbuseIPDB e dos IPs
# associados: o dominio em si nunca tem placar ali. O AbuseIPDB governa duas na aba de IP --
# o placar e o nome de dominio, que vem na mesma resposta e some junto com ela.
COLUNAS = {
    "ip": {"abuse": ("abuse", "dominio"), "vt": ("vt",), "md": ("md",), "local": ("pais",)},
    "hash": {"vt": ("vt",), "alien": ("alien",), "md": ("md",), "joe": ("joe",)},
    "url": {"vt": ("vt",), "alien": ("alien",), "md": ("md",), "ips": ("abuse",)},
}


# O X-Force deixou de ser consultado em 09/2026: a IBM fechou o portal atras de login e o
# acesso por API passou a exigir plano comercial. Ele voltou como fonte de referencia, so o
# endereco da pagina no relatorio, para quem quiser abrir e conferir a mao. Vem desmarcado
# porque a maioria nao abre o portal, e a escolha de quem marcar fica guardada.
DESLIGADAS_POR_PADRAO = frozenset({"ibm"})


def todas(aba):
    return {chave for chave, _rotulo, _tipo in CATALOGO[aba]}


def padrao(aba):
    """O que vem marcado quando o app abre. `todas` segue existindo para o botao do modal."""
    return todas(aba) - DESLIGADAS_POR_PADRAO


def tem_navegador(aba):
    """Ha fonte por navegador na aba? E o que da sentido ao atalho "so as rapidas"."""
    return any(tipo == NAVEGADOR for _chave, _rotulo, tipo in CATALOGO[aba])


def rapidas(aba):
    return {chave for chave, _rotulo, tipo in CATALOGO[aba] if tipo == API}


def escolha_salva(aba, guardadas):
    """Escolha do disco filtrada pelo catalogo de hoje, ou o padrao quando nao serve.

    Fonte que saiu do catalogo entre versoes e ignorada, e escolha vazia cai no padrao: sem
    isso um arquivo estragado poderia deixar a aba sem consultar fonte nenhuma, e a tela
    diria "limpo" sem ter perguntado a ninguem.
    """
    if not isinstance(guardadas, dict):
        return padrao(aba)
    validas = {chave for chave in guardadas.get(aba) or () if chave in todas(aba)}
    return validas or padrao(aba)


def usa_navegador(aba, ativas):
    """Alguma fonte marcada depende de Chrome? E o que decide subir o pool."""
    return any(tipo == NAVEGADOR and chave in ativas
               for chave, _rotulo, tipo in CATALOGO[aba])


def referencias(aba, ativas):
    """Marcadas que so entram como link no relatorio e na planilha, sem consulta nenhuma."""
    return {chave for chave, _rotulo, tipo in CATALOGO[aba]
            if tipo == REFERENCIA and chave in ativas}


def desligadas(aba, ativas):
    """Fontes consultaveis que ficaram de fora. Referencia nao entra: nao consultada de
    origem, ela apareceria no resumo como base faltando."""
    return [chave for chave, _rotulo, tipo in CATALOGO[aba]
            if chave not in ativas and tipo != REFERENCIA]


def colunas_ocultas(aba, ativas):
    return {coluna
            for chave in desligadas(aba, ativas) if chave in COLUNAS[aba]
            for coluna in COLUNAS[aba][chave]}


def rotulo(aba, chave):
    return next(r for c, r, _tipo in CATALOGO[aba] if c == chave)
