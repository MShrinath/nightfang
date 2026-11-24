@echo off
setlocal enabledelayedexpansion

if "%HERMES_HOME%"=="" set "HERMES_HOME=%USERPROFILE%\.hermes"

if exist "%~dp0tools\gateway.py" (
    set "NIGHTFANG_ROOT=%~dp0"
) else if exist "%~dp0..\..\tools\gateway.py" (
    set "NIGHTFANG_ROOT=%~dp0..\.."
) else (
    set "NIGHTFANG_ROOT=%~dp0..\.."
)
for %%I in ("%NIGHTFANG_ROOT%") do set "NIGHTFANG_ROOT=%%~fI"

set "HERMES_SYSTEM_PROMPT=%HERMES_HOME%\nightfang\system.md"
set "HERMES_CONFIG=%HERMES_HOME%\nightfang\config.yaml"

echo [NIGHTFANG] Security Intelligence Layer (Active)
echo 46 Specialized Agents ^| 42 Capabilities ^| Autonomous Hunter: READY
echo.

if "%~1"=="--daemon" goto :run_daemon
if "%~1"=="--hunt" goto :run_hunt
if "%~1"=="--test" (
    python "%NIGHTFANG_ROOT%\tools\daemon.py" --test
    python "%NIGHTFANG_ROOT%\tools\gateway.py"
    python "%NIGHTFANG_ROOT%\tools\sandbox.py"
    python "%NIGHTFANG_ROOT%\schemas\validator.py" --test
    python "%NIGHTFANG_ROOT%\tools\mcp_proxy.py" --test
    python "%NIGHTFANG_ROOT%\tools\ingest.py" --test
    python "%NIGHTFANG_ROOT%\tools\hud.py" --test
    goto :eof
)
if "%~1"=="--test-all" (
    python "%NIGHTFANG_ROOT%\tools\daemon.py" --test
    python "%NIGHTFANG_ROOT%\tools\gateway.py"
    python "%NIGHTFANG_ROOT%\tools\sandbox.py"
    python "%NIGHTFANG_ROOT%\schemas\validator.py" --test
    python "%NIGHTFANG_ROOT%\tools\mcp_proxy.py" --test
    python "%NIGHTFANG_ROOT%\tools\ingest.py" --test
    python "%NIGHTFANG_ROOT%\tools\hud.py" --test
    python "%NIGHTFANG_ROOT%\tools\simulation.py" --test
    goto :eof
)

where hermes >nul 2>&1
if %ERRORLEVEL% equ 0 (
    hermes %*
) else (
    echo [*] Hermes binary not detected in PATH.
    if not "%~1"=="" (
        python "%NIGHTFANG_ROOT%\tools\daemon.py" %*
    ) else (
        echo Usage:
        echo   nightfang --daemon --target <domain>    Run continuous autonomous hunter
        echo   nightfang --hunt <domain>               Launch autonomous attack chain
        echo   nightfang --test                        Run tool self-tests
        echo   nightfang --test-all                    Run all self-tests and E2E simulation
        echo.
        echo Starting interactive Autonomous Hunter session...
        python -i -c "import sys; sys.path.insert(0, r'%NIGHTFANG_ROOT%\tools'); from daemon import AutonomousHunterDaemon; from gateway import ExecutionPolicyGateway; print('[*] NIGHTFANG Autonomous Hunter and Gateway loaded.')"
    )
)
goto :eof

:run_daemon
shift
set "NF_ARGS="
:daemon_loop
if not "%~1"=="" (
    set "NF_ARGS=!NF_ARGS! %1"
    shift
    goto :daemon_loop
)
python "%NIGHTFANG_ROOT%\tools\daemon.py"%NF_ARGS%
goto :eof

:run_hunt
shift
set "NF_ARGS="
:hunt_loop
if not "%~1"=="" (
    set "NF_ARGS=!NF_ARGS! %1"
    shift
    goto :hunt_loop
)
python "%NIGHTFANG_ROOT%\tools\daemon.py" --continuous%NF_ARGS%
goto :eof
