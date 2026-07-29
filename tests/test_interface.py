"""Interface: thread-safety, render incremental, tabela ordenavel, atalhos e i18n.

Nao toca em rede nem em Selenium.
"""
import time
import tkinter as tk
from tkinter import ttk

from _comum import check, encerrar

import app as gui
import i18n
from i18n import t
from ui import apresentacao, tema

gui.IPCheckerApp._init_drivers_async = lambda self, count=3: None

root = tk.Tk()
tema.configurar_estilos(ttk.Style())
root.withdraw()
app = gui.IPCheckerApp(root)
gui.app = app


def linha_ip(indice, ip, status, abuse, vt, ibm, pais):
    colunas = (ip, t(apresentacao.VERDICT_KEYS[status]), abuse, vt, ibm, pais)
    texto = f"[{indice}] {ip} - {status}\nScore: {vt}\n- https://exemplo/{ip}"
    data = {"ip": ip, "status": status, "estados": {}, "fontes_indisponiveis": []}
    return (indice, [ip], texto, ip, status, colunas, data)


print("\n[1] Estado inicial")
check(str(app.copy_button["state"]) == "disabled", "Copiar comeca desabilitado")
check(str(app.save_button["state"]) == "disabled", "Exportar comeca desabilitado")
check(str(app.cancel_button["state"]) == "disabled", "Cancelar comeca desabilitado")
check(app.tabela_ip.is_empty(), "tabela de IP comeca vazia")
check(t("detail_hint") in app.tabela_ip.detalhe.get("1.0", tk.END), "painel mostra a dica inicial")

print("\n[2] Contadores ao vivo da entrada")
check(apresentacao.contar_ips("8.8.8.8 1.1.1.1") == "2 válidos", "conta so validos")
resumo = apresentacao.contar_ips("8.8.8.8, abc, 10.0.0.1")
check("1 válidos" in resumo and "1 inválidos" in resumo and "1 privados" in resumo,
      f"separa valido/invalido/privado ({resumo})")
check(apresentacao.contar_ips("") == "", "entrada vazia nao mostra contador")
check(apresentacao.contar_hashes("d41d8cd98f00b204e9800998ecf8427e xyz") == "1 válidos · 1 inválidos",
      "contador de hash separa invalidos")
check(apresentacao.contar_dominios("a.com b.com") == "2 válidos", "contador de dominios")
check(apresentacao.contar_dominios("a.com lixo colado") == "1 válidos · 2 inválidos",
      "contador de dominios separa invalidos, como o de IP e o de hash")
app.entry.texto.insert("1.0", "8.8.8.8 abc")
app.entry.refresh()
check("inválidos" in app.entry.resumo["text"], "contador do campo atualiza ao digitar")

print("\n[3] Render incremental em tabela")
app.total_ip, app.feitos_ip = 3, 0
app.append_ip_results([linha_ip(1, "1.1.1.1", "clean", "0%", 0, "1.0", "Brasil")])
app.append_ip_results([linha_ip(2, "2.2.2.2", "bad", "100%", 42, "9.0", "Rússia")])
app.append_ip_results([linha_ip(3, "3.3.3.3", "whitelisted_bad", "0%", 5, "8.0", "China")])
filhos = app.tabela_ip.tree.get_children("")
check(len(filhos) == 3, "tres linhas na tabela")
check(list(filhos) == ["ip-1", "ip-2", "ip-3"], "ordem de chegada preservada")
check(app.bad_ips == {"2.2.2.2"} and app.review_ips == {"3.3.3.3"}, "status classificados")
check(app.tabela_ip.tree.item("ip-2", "tags")[0] == "bad", "linha maliciosa marcada")
check(app.tabela_ip.tree.item("ip-3", "tags")[0] == "review", "linha de revisao marcada")

print("\n[4] Veredito nao depende so de cor")
check(app.tabela_ip.tree.set("ip-1", "veredito") == t("verdict_clean"), "● Limpo")
check(app.tabela_ip.tree.set("ip-2", "veredito") == t("verdict_bad"), "✖ Malicioso")
check(app.tabela_ip.tree.set("ip-3", "veredito") == t("verdict_review"), "▲ Revisar")

print("\n[5] Ordenacao por coluna")
app.tabela_ip._ordenar("vt")
check(list(app.tabela_ip.tree.get_children("")) == ["ip-1", "ip-3", "ip-2"], "ordena VT crescente")
app.tabela_ip._ordenar("vt")
check(list(app.tabela_ip.tree.get_children("")) == ["ip-2", "ip-3", "ip-1"], "segundo clique inverte")
app.tabela_ip._ordenar("#0")
check(list(app.tabela_ip.tree.get_children("")) == ["ip-1", "ip-2", "ip-3"], "ordena pela coluna de arvore")

print("\n[6] Detalhe da linha selecionada e links clicaveis")
app.tabela_ip.tree.selection_set("ip-2")
root.update()
detalhe = app.tabela_ip.detalhe.get("1.0", tk.END)
check("2.2.2.2" in detalhe, "detalhe mostra a linha selecionada")
check("1.1.1.1" not in detalhe, "detalhe nao mistura outras linhas")
check(any(n.startswith("link") for n in app.tabela_ip.detalhe.tag_names()), "URL recebeu tag de link")

print("\n[7] Relatorio completo para o Copiar")
app.ignorados_ip = ["10.0.0.1 (IP privado)"]
app.pre_var_ip.set(False)
app._append_analysis()
relatorio = app.tabela_ip.report()
check(all(ip in relatorio for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3")), "relatorio traz os tres IPs")
check(t("skipped_items") in relatorio, "relatorio lista os ignorados")
check(relatorio.index("1.1.1.1") < relatorio.index("2.2.2.2"), "relatorio segue a ordem de chegada")
app.pre_var_ip.set(True)
app._append_analysis()
check("2.2.2.2" in app.tabela_ip.report().split("\n\n")[1], "pre-analise entra no topo do relatorio")

print("\n[8] Barra de progresso determinada")
app.scanning_ip = True
app.feitos_ip = 0
app._avancar_ip()
app._avancar_ip()
check(int(app.progress_ip["value"]) == 2, "barra avanca com as conclusoes")
check(int(app.progress_ip["maximum"]) == 3, "maximo e o total de itens")
check("2/3" in app.status_label["text"], f"status mostra a contagem ({app.status_label['text']})")

print("\n[9] Erro vira linha, nao caixa de dialogo")
app._linha_erro_ip(9, "4.4.4.4", "timeout")
check("ip-erro-9" in app.tabela_ip.tree.get_children(""), "IP com erro entrou como linha")
check(app.tabela_ip.tree.set("ip-erro-9", "veredito") == t("verdict_unknown"), "erro marcado indisponivel")

print("\n[10] IPs associados como filhos do dominio")
app.tabela_url.clear()
app._linha_url(1, ("exemplo.com", t("verdict_bad"), "-", 3, "8.0", "2"), "exemplo.com\ndetalhe", "bad")
app._linha_url_filha(1, 1, ("9.9.9.9", t("verdict_clean"), "0%", 0, "1.0", "-"), "9.9.9.9\ndetalhe", "clean")
check(list(app.tabela_url.tree.get_children("")) == ["url-1"], "dominio e linha raiz")
check(list(app.tabela_url.tree.get_children("url-1")) == ["url-1-ip-1"], "IP associado e filho do dominio")
check("9.9.9.9" in app.tabela_url.report(), "relatorio inclui o IP associado")

print("\n[11] Mensagens finais e cancelamento")
app.scanning_ip = False
app._finish_ip_scan()
check(app.status_label["text"].startswith("✅"), "conclusao no status")
app.update_status_label()
check(app.status_label["text"].startswith("✅"), "conclusao sobrevive a callback atrasado")
app.scanning_ip = True
app.cancel_check()
check(app.status_label["text"].startswith("❌"), "cancelamento no status")
app.update_status_label()
check(app.status_label["text"].startswith("❌"), "cancelamento sobrevive a callback atrasado")

print("\n[12] Atalhos")
check(app.entry.texto.bind("<Control-Return>") != "", "Ctrl+Enter no campo de IP")
check(app.hash_entry.texto.bind("<Control-Return>") != "", "Ctrl+Enter no campo de hash")
check(app.url_entry.texto.bind("<Control-Return>") != "", "Ctrl+Enter no campo de dominio")
check(root.bind("<Escape>") != "", "Esc ligado na janela")
app.current_page = "hash"
app.scanning_hash = False
app.hash_status_label.config(text="")
app.cancel_current()
check(app.hash_status_label["text"] == "", "Esc sem varredura nao faz nada")

print("\n[13] Troca de idioma reetiqueta a tabela")
cabecalho_pt = app.tabela_ip.tree.heading("veredito")["text"]
i18n.definir_idioma("en")
app.refresh_language()
cabecalho_en = app.tabela_ip.tree.heading("veredito")["text"]
check(cabecalho_pt == "Veredito" and cabecalho_en == "Verdict",
      f"cabecalho traduzido ({cabecalho_pt} -> {cabecalho_en})")
check("valid" in app.entry.resumo["text"], "contador traduzido junto")
i18n.definir_idioma("pt")
app.refresh_language()

print("\n[14] Exportacao nao cria uma segunda raiz Tk")
import threading

from services import exportacao
from ui import aba_ip, janela_atualizacao

pedidos = []
exportacao.filedialog.askdirectory = lambda **kw: pedidos.append(kw) or "C:\\saida"
app.results_ip = [["1.1.1.1", "0%", 0]]
app.ibm_ip_ativo = False
aba_ip.salvar_planilha = lambda *a, **kw: exportacao.escolher_diretorio(kw.get("parent"), kw.get("titulo"))
app.save_results()
check(len(pedidos) == 1, "o dialogo de pasta abriu")
check(pedidos[0].get("parent") is root, "dialogo usa a janela existente como dona")
check(pedidos[0].get("title") == t("select_folder"), "titulo traduzido, sem citar CSV")
check(tk._default_root is root, "nenhuma segunda raiz Tk virou a padrao")

print("\n[15] Verificacao de versao nao segura a janela")
liberado = threading.Event()
janela_atualizacao.versao_mais_recente = lambda v: (liberado.wait(5), (None, None))[1]
inicio = time.time()
t_versao = threading.Thread(target=janela_atualizacao.verificar_em_segundo_plano,
                            args=(root, "v0"), daemon=True)
t_versao.start()
check(time.time() - inicio < 0.5, "a verificacao roda fora da thread da interface")
check(t_versao.is_alive(), "segue em segundo plano enquanto a janela ja esta de pe")
liberado.set()
t_versao.join(timeout=5)

print("\n[16] As fronteiras dos modulos estao respeitadas")
import core.api
import core.reputacao
import ui.apresentacao
import ui.widgets

for modulo in (core.api, core.reputacao):
    fontes = [n for n in dir(modulo) if n.startswith(("ui.", "tk"))]
    check(not fontes, f"{modulo.__name__} nao importa a interface")
check("tkinter" not in str(core.reputacao.__dict__.get("__builtins__", "")), "nucleo sem Tk")
check(hasattr(ui.widgets, "ResultTable") and not hasattr(ui.widgets, "build_ip_result"),
      "widgets nao carregam regra de negocio")

root.destroy()
encerrar()
