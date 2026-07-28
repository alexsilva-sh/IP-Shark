@echo off
rem ============================================================
rem  IP Shark - suites de teste (sem rede, sem Selenium, sem Chrome)
rem  Uso:  run_tests.bat [deps]
rem ============================================================
setlocal EnableExtensions EnableDelayedExpansion
pushd "%~dp0"

echo.
echo === IP Shark - testes ===
call "%~dp0_ambiente.bat" %1
if errorlevel 1 goto falhou

set /a TOTAL=0
set /a QUEBRADAS=0
set "LISTA_QUEBRADA="

for %%T in ("tests\test_*.py") do (
    set /a TOTAL+=1
    echo.
    echo --- %%~nxT ---
    "%VPY%" "%%~fT"
    if errorlevel 1 (
        set /a QUEBRADAS+=1
        set "LISTA_QUEBRADA=!LISTA_QUEBRADA! %%~nxT"
    )
)

echo.
if !QUEBRADAS! EQU 0 (
    echo === !TOTAL! suite^(s^): todas passaram ===
) else (
    echo === !QUEBRADAS! de !TOTAL! suite^(s^) falharam:!LISTA_QUEBRADA! ===
    goto falhou
)

popd
endlocal
exit /b 0

:falhou
echo.
echo *** TESTES FALHARAM ***
popd
endlocal
exit /b 1
