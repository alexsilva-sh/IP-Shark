# -*- mode: python ; coding: utf-8 -*-
import sys

a = Analysis(
    ['src\\ip_checker_gui_dark.py'],
    # src no pathex: os modulos entram como codigo, seguindo os imports. Antes iam
    # como datas soltos, o que exigia listar cada arquivo novo aqui a mao.
    pathex=['src'],
    binaries=[],
    # Os locales sao lidos por caminho em tempo de execucao, entao continuam como datas.
    # Nao inclua config/api.env aqui: isso embute as chaves dentro do .exe distribuido.
    datas=[('assets/shark.ico', 'assets'), ('src/locales/pt_BR.py', 'locales'), ('src/locales/en_US.py', 'locales')],
    hiddenimports=['openpyxl', 'pyperclip', 'bs4', 'selenium', 'webdriver_manager'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
# O hook do Selenium recolhe o selenium-manager das tres plataformas. Num build Windows
# os de Linux e macOS sao 12,9 MB que o _get_binary() do Selenium nunca vai escolher --
# ele resolve por sys.platform. O de Windows entra como BINARY, nao como DATA, entao
# nao ha risco de este filtro derrubar o unico que importa.
if sys.platform == 'win32':
    _outras = ('/linux/', '/macos/')
    _antes = len(a.datas)
    a.datas = [entrada for entrada in a.datas
               if 'selenium-manager' not in entrada[0]
               or not any(p in entrada[0].replace('\\', '/') for p in _outras)]
    print(f'[spec] selenium-manager de outras plataformas removido: {_antes - len(a.datas)} arquivo(s)')

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='ipshark',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['assets\\shark.ico'],
)
