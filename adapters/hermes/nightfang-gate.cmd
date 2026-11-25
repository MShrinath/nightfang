@echo off
setlocal enabledelayedexpansion

if "%HERMES_HOME%"=="" set "HERMES_HOME=%USERPROFILE%\.hermes"

if exist "%~dp0tools\gateway.py" (
    set "NIGHTFANG_ROOT=%~dp0"
) else if exist "%~dp0..\..\tools\gateway.py" (
    set "NIGHTFANG_ROOT=%~dp0..\.."
) else if exist "%HERMES_HOME%\nightfang\installation.json" (
    for /f "delims=" %%I in ('python -c "import json; d=json.load(open(r'%HERMES_HOME%\nightfang\installation.json', encoding='utf-8-sig')); print(d.get('nightfang_root') or d.get('root', ''))" 2^>nul') do (
        set "NIGHTFANG_ROOT=%%~I"
    )
    if not exist "!NIGHTFANG_ROOT!\tools\gateway.py" (
        for /f "usebackq delims=" %%I in (`powershell -NoProfile -Command "(Get-Content -Raw -Encoding UTF8 '%HERMES_HOME%\nightfang\installation.json' | ConvertFrom-Json).nightfang_root" 2^>nul`) do (
            if exist "%%~I\tools\gateway.py" set "NIGHTFANG_ROOT=%%~I"
        )
    )
) else (
    set "NIGHTFANG_ROOT=%~dp0..\.."
)
for %%I in ("%NIGHTFANG_ROOT%") do set "NIGHTFANG_ROOT=%%~fI"

python "%NIGHTFANG_ROOT%\tools\gateway.py" %*

