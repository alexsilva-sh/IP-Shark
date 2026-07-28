# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['src\\ip_checker_gui_dark.py'],
    pathex=[],
    binaries=[],
    # Nao inclua config/api.env aqui: isso embute as chaves dentro do .exe distribuido.
    datas=[('assets/shark.ico', 'assets'), ('src/locales/pt_BR.py', 'locales'), ('src/locales/en_US.py', 'locales'), ('src/country_codes.py', '.'), ('src/ip_checker_core.py', '.'), ('src/secure_store.py', '.')],
    hiddenimports=['openpyxl', 'pyperclip', 'bs4', 'selenium', 'webdriver_manager'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
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
