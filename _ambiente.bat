@echo off
rem ============================================================
rem  Prepara o ambiente compartilhado por build.bat e run_tests.bat.
rem  Chamado com CALL, sem setlocal: exporta VPY, TCL_LIBRARY e TK_LIBRARY.
rem  Uso:  call _ambiente.bat [deps]
rem ============================================================

set "VENV=.venv"
set "VPY=%VENV%\Scripts\python.exe"

rem --- Interpretador -----------------------------------------
set "PYBOOT="
py -3 --version >nul 2>&1
if not errorlevel 1 set "PYBOOT=py -3"
if not defined PYBOOT (
    python --version >nul 2>&1
    if not errorlevel 1 set "PYBOOT=python"
)
if not defined PYBOOT (
    echo [ERRO] Python nao encontrado no PATH. Instale o Python 3 e tente de novo.
    exit /b 1
)

rem --- Ambiente virtual --------------------------------------
if exist "%VPY%" (
    echo   Ambiente virtual: %VENV%
) else (
    echo   Criando ambiente virtual em %VENV% ...
    %PYBOOT% -m venv "%VENV%"
    if errorlevel 1 exit /b 1
)

rem --- Dependencias ------------------------------------------
if /i "%~1"=="deps" (
    echo   Instalando dependencias de requirements.txt ...
    "%VPY%" -m pip install --upgrade pip --disable-pip-version-check -q
    if errorlevel 1 exit /b 1
    "%VPY%" -m pip install -r requirements.txt --disable-pip-version-check -q
    if errorlevel 1 exit /b 1
)

rem --- Tcl/Tk ------------------------------------------------
rem venv no Windows nao copia o diretorio tcl\, entao _tkinter nao acha o init.tcl
rem e o PyInstaller descarta o tkinter, gerando um .exe que nao abre.
set "PROBE=%TEMP%\ipshark_tcl_%RANDOM%.txt"
"%VPY%" -c "import sys,os,glob;b=sys.base_prefix;g=lambda p,f:next((d for d in sorted(glob.glob(os.path.join(b,'tcl',p))) if os.path.isfile(os.path.join(d,f))),'');print(g('tcl[89]*','init.tcl'));print(g('tk[89]*','tk.tcl'))" > "%PROBE%"
if errorlevel 1 exit /b 1
set "TCL_LIBRARY="
set "TK_LIBRARY="
set /a LINHA=0
for /f "usebackq delims=" %%L in ("%PROBE%") do (
    set /a LINHA+=1
    if !LINHA!==1 set "TCL_LIBRARY=%%L"
    if !LINHA!==2 set "TK_LIBRARY=%%L"
)
del "%PROBE%" >nul 2>&1
"%VPY%" -c "import tkinter; r = tkinter.Tk(); r.destroy()" 2>nul
if errorlevel 1 (
    echo [ERRO] tkinter nao funciona neste ambiente.
    echo        TCL_LIBRARY=!TCL_LIBRARY!
    echo        TK_LIBRARY=!TK_LIBRARY!
    echo        Verifique se o Python foi instalado com o componente "tcl/tk and IDLE".
    exit /b 1
)

exit /b 0
