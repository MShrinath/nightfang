@echo off
if exist "%~dp0tools\gateway.py" (
    set "NIGHTFANG_ROOT=%~dp0"
) else if exist "%~dp0..\..\tools\gateway.py" (
    set "NIGHTFANG_ROOT=%~dp0..\.."
) else (
    set "NIGHTFANG_ROOT=C:\Users\shrin\Music\nightfang"
)
for %%I in ("%NIGHTFANG_ROOT%") do set "NIGHTFANG_ROOT=%%~fI"
python "%NIGHTFANG_ROOT%\tools\gateway.py" %*
