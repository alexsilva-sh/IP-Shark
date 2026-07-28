@echo off
rem ============================================================
rem  IP Shark - build padronizado do executavel
rem  Uso:  build.bat [fast] [run] [publish] [clean] [help]
rem ============================================================
setlocal EnableExtensions EnableDelayedExpansion
pushd "%~dp0"

set "ALVO=dist\ipshark.exe"
set "DO_FAST="
set "DO_RUN="
set "DO_PUBLISH="
set "DO_CLEAN="
set "DO_HELP="

:parse
if "%~1"=="" goto parsed
set "ARG=%~1"
set "ARG=%ARG:/=%"
set "ARG=%ARG:-=%"
if /i "!ARG!"=="fast"    (set "DO_FAST=1")    else ^
if /i "!ARG!"=="run"     (set "DO_RUN=1")     else ^
if /i "!ARG!"=="publish" (set "DO_PUBLISH=1") else ^
if /i "!ARG!"=="clean"   (set "DO_CLEAN=1")   else ^
if /i "!ARG!"=="help"    (set "DO_HELP=1")    else ^
if /i "!ARG!"=="?"       (set "DO_HELP=1")    else (
    echo [ERRO] Opcao desconhecida: %~1
    set "DO_HELP=1"
)
shift
goto parse
:parsed

if defined DO_HELP (
    echo.
    echo   build.bat            Build limpo: venv + dependencias + PyInstaller
    echo   build.bat fast       Reaproveita o cache de build e pula o pip install
    echo   build.bat run        Abre o executavel ao final
    echo   build.bat publish    Copia dist\ipshark.exe para a raiz do projeto
    echo   build.bat clean      So apaga build\ e dist\ e sai
    echo.
    echo   As opcoes podem ser combinadas:  build.bat fast run
    echo.
    goto fim
)

echo.
echo === IP Shark - build ===

if defined DO_CLEAN (
    call :limpar
    echo Artefatos removidos.
    goto fim
)

rem --- 1. Ambiente (venv, dependencias, Tcl/Tk) ---------------
echo [1/4] Preparando o ambiente ...
if defined DO_FAST (
    call "%~dp0_ambiente.bat"
) else (
    call "%~dp0_ambiente.bat" deps
)
if errorlevel 1 goto falhou

rem --- 2. Limpeza (guarda o tamanho anterior p/ comparar) -----
set "PREV="
if exist "%ALVO%" for %%A in ("%ALVO%") do set "PREV=%%~zA"

if defined DO_FAST (
    echo [2/4] Limpeza: pulado ^(fast^)
) else (
    echo [2/4] Limpando build\ e dist\ ...
    call :limpar
)

rem --- 3. PyInstaller ----------------------------------------
if not exist "assets\shark.ico" (
    echo [ERRO] assets\shark.ico nao encontrado.
    goto falhou
)
echo [3/4] Gerando o executavel com ipshark.spec ...
"%VPY%" -m PyInstaller --noconfirm --log-level WARN ipshark.spec
if errorlevel 1 goto falhou

if not exist "%ALVO%" (
    echo [ERRO] O PyInstaller terminou mas %ALVO% nao existe.
    goto falhou
)
if exist "build\ipshark\Analysis-00.toc" (
    findstr /i /c:"init.tcl" "build\ipshark\Analysis-00.toc" >nul
    if errorlevel 1 (
        echo [ERRO] O bundle saiu sem os arquivos do Tcl/Tk - a janela nao vai abrir.
        goto falhou
    )
)

rem --- Resultado ---------------------------------------------
for %%A in ("%ALVO%") do set "SIZE=%%~zA"
set /a TENTHS=SIZE*10/1048576
set /a MB_INT=TENTHS/10
set /a MB_DEC=TENTHS %% 10
echo [4/4] Pronto: %ALVO%  ^(!MB_INT!.!MB_DEC! MB^)

if defined PREV (
    set /a DELTA=SIZE-PREV
    set /a PCT=DELTA*100/PREV
    if !DELTA! GTR 0 (
        echo       Variacao desde o build anterior: +!PCT!%%
        rem MELHORIAS.md 3.6: crescimento acima de ~10%% precisa de justificativa.
        if !PCT! GEQ 10 echo       [AVISO] Crescimento acima de 10%% - vale investigar o que entrou no bundle.
    ) else (
        echo       Variacao desde o build anterior: !PCT!%%
    )
)

if defined DO_PUBLISH (
    echo       Copiando para ipshark.exe na raiz ...
    copy /y "%ALVO%" "ipshark.exe" >nul
    if errorlevel 1 goto falhou
)

echo.
echo Antes de publicar, teste as tres abas ^(IP, Hash, Dominio^) com o .exe gerado.

if defined DO_RUN (
    echo Abrindo %ALVO% ...
    start "" "%ALVO%"
)

goto fim

:limpar
if exist "build" rmdir /s /q "build"
if exist "dist" rmdir /s /q "dist"
exit /b 0

:falhou
echo.
echo *** BUILD FALHOU ***
popd
endlocal
exit /b 1

:fim
popd
endlocal
exit /b 0
