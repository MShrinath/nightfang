@echo off
setlocal enabledelayedexpansion

if "%HERMES_HOME%"=="" set "HERMES_HOME=%USERPROFILE%\.hermes"

if exist "%~dp0tools\gateway.py" (
    set "NIGHTFANG_ROOT=%~dp0"
) else if exist "%~dp0..\..\tools\gateway.py" (
    set "NIGHTFANG_ROOT=%~dp0..\.."
) else (
    set "NIGHTFANG_ROOT=C:\Users\shrin\Music\nightfang"
)
for %%I in ("%NIGHTFANG_ROOT%") do set "NIGHTFANG_ROOT=%%~fI"

set "HERMES_SYSTEM_PROMPT=%HERMES_HOME%\nightfang\system.md"
set "HERMES_CONFIG=%HERMES_HOME%\nightfang\config.yaml"

echo [NIGHTFANG] Security Intelligence Layer (Active)
echo 37 Specialized Agents ^| 33 Capabilities ^| Autonomous Hunter: READY
echo.

if "%~1"=="--daemon" (
    shift
    python "%NIGHTFANG_ROOT%\tools\daemon.py" %*
    goto :eof
)
if "%~1"=="--hunt" (
    shift
    python "%NIGHTFANG_ROOT%\tools\daemon.py" --continuous %*
    goto :eof
)
if "%~1"=="--test" (
    python "%NIGHTFANG_ROOT%\tools\daemon.py" --test
    python "%NIGHTFANG_ROOT%\tools\gateway.py"
    goto :eof
)

where hermes >nul 2>&1
if %ERRORLEVEL% equ 0 (
    hermes --system-prompt "%HERMES_SYSTEM_PROMPT%" --config "%HERMES_CONFIG%" %*
) else (
    echo [*] Hermes binary not detected in PATH.
    if not "%~1"=="" (
        python "%NIGHTFANG_ROOT%\tools\daemon.py" %*
    ) else (
        echo Usage:
        echo   nightfang --daemon --target <domain>    Run continuous autonomous hunter
        echo   nightfang --hunt <domain>               Launch autonomous attack chain
        echo   nightfang --test                        Run gateway and daemon self-tests
        echo.
        echo Starting interactive Autonomous Hunter session...
        python -i -c "import sys; sys.path.insert(0, r'%NIGHTFANG_ROOT%\tools'); from daemon import AutonomousHunterDaemon; from gateway import ExecutionPolicyGateway; print('[*] NIGHTFANG Autonomous Hunter and Gateway loaded.')"
    )
)
