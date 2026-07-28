"""Estilos ttk do tema escuro."""

FUNDO = "#1e1e1e"
FUNDO_CAMPO = "#2a2a2a"
FUNDO_TABELA = "#0f0f0f"
FUNDO_AVISO = "#3a2a12"

TEXTO = "#dddddd"
TEXTO_SECUNDARIO = "#9aa0a6"
LINK = "#4da3ff"

LIMPO = "#00ff99"
REVISAR = "#ffb020"
MALICIOSO = "#ff4444"
INDISPONIVEL = "#9aa0a6"


def configurar_estilos(style):
    style.theme_use("clam")   # trocar de tema descarta o que ja foi configurado
    style.configure("Nav.TButton",background="#333333",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.map("Nav.TButton",background=[("active","#444444")])
    style.configure("NavActive.TButton",background="#007acc",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.configure("Secondary.TButton",background="#333333",foreground="white",font=("Segoe UI",10),padding=(10,5))
    style.map("Secondary.TButton",background=[("disabled","#262626"),("active","#222222"),("pressed","#1a1a1a")],foreground=[("disabled","#6b6b6b"),("active","white")])
    style.configure("Danger.TButton",background="#aa0000",foreground="white",font=("Segoe UI",10,"bold"),padding=(10,5))
    style.map("Danger.TButton",background=[("disabled","#3a2222"),("active","#7a0000"),("pressed","#5c0000")],foreground=[("disabled","#8a6b6b"),("active","white")])
    style.configure("Primary.TButton",background="#007acc",foreground="white",font=("Segoe UI",10,"bold"),padding=(12,6))
    style.map("Primary.TButton",background=[("disabled","#2b3a45"),("active","#1e90ff"),("pressed","#0060a8")],foreground=[("disabled","#7a8b96"),("active","white")])
    style.configure("Custom.TEntry",fieldbackground=FUNDO_CAMPO,foreground="white",padding=6)
    style.configure("Status.TLabel",background=FUNDO,foreground="#00c853",font=("Segoe UI",9))
    style.configure("Title.TLabel",background=FUNDO,foreground="white",font=("Segoe UI",11,"bold"))
    style.configure("Result.Treeview",background=FUNDO_TABELA,fieldbackground=FUNDO_TABELA,foreground=TEXTO,font=("Consolas",10),rowheight=24,borderwidth=0)
    style.map("Result.Treeview",background=[("selected","#0a3d5c")],foreground=[("selected","white")])
    style.configure("Result.Treeview.Heading",background=FUNDO_CAMPO,foreground="white",font=("Segoe UI",9,"bold"),relief="flat",padding=(6,5))
    style.map("Result.Treeview.Heading",background=[("active","#3a3a3a")])
    style.configure("Scan.Horizontal.TProgressbar",troughcolor=FUNDO_CAMPO,bordercolor=FUNDO_CAMPO,background="#007acc",lightcolor="#007acc",darkcolor="#007acc",thickness=8)
