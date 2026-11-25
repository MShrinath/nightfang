@echo off
setlocal enabledelayedexpansion

if "%HERMES_HOME%"=="" set "HERMES_HOME=%USERPROFILE%\.hermes"
set "NIGHTFANG_ROOT=%~dp0"
if "%NIGHTFANG_ROOT:~-1%"=="\" set "NIGHTFANG_ROOT=%NIGHTFANG_ROOT:~0,-1%"

set "HERMES_SYSTEM_PROMPT=%HERMES_HOME%\nightfang\system.md"
set "HERMES_CONFIG=%HERMES_HOME%\nightfang\config.yaml"

echo [NIGHTFANG] Security Intelligence Layer (Active)
echo 46 Specialized Agents ^| 42 Capabilities ^| Autonomous Hunter: READY
echo.

if "%~1"=="--daemon" goto :run_daemon
if "%~1"=="--hunt" goto :run_hunt
if "%~1"=="--status-card" goto :run_status_card
if "%~1"=="--sync" goto :run_sync
if "%~1"=="--verify" goto :run_verify
if "%~1"=="--verify-canary" goto :run_verify_canary
if "%~1"=="--ingest" goto :run_ingest
if "%~1"=="--list-findings" goto :run_list_findings
if "%~1"=="--test" goto :run_test
if "%~1"=="--test-all" goto :run_test_all

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

:run_status_card
shift
set "NF_ARGS="
:status_loop
if not "%~1"=="" (
    set "NF_ARGS=!NF_ARGS! %1"
    shift
    goto :status_loop
)
python "%NIGHTFANG_ROOT%\tools\daemon.py" --card status!NF_ARGS!
goto :eof

:run_sync
shift
set "NF_ARGS="
:sync_loop
if not "%~1"=="" (
    set "NF_ARGS=!NF_ARGS! %1"
    shift
    goto :sync_loop
)
python "%NIGHTFANG_ROOT%\tools\findings.py" --sync!NF_ARGS!
goto :eof

:run_verify
shift
set "NF_ARGS="
:verify_loop
if not "%~1"=="" (
    set "NF_ARGS=!NF_ARGS! %1"
    shift
    goto :verify_loop
)
python "%NIGHTFANG_ROOT%\tools\findings.py" --verify!NF_ARGS!
goto :eof

:run_verify_canary
shift
set "NF_ARGS="
:canary_loop
if not "%~1"=="" (
    set "NF_ARGS=!NF_ARGS! %1"
    shift
    goto :canary_loop
)
python "%NIGHTFANG_ROOT%\tools\findings.py" --verify-canary!NF_ARGS!
goto :eof

:run_ingest
shift
set "NF_ARGS="
:ingest_loop
if not "%~1"=="" (
    set "NF_ARGS=!NF_ARGS! %1"
    shift
    goto :ingest_loop
)
python "%NIGHTFANG_ROOT%\tools\findings.py" --ingest!NF_ARGS!
goto :eof

:run_list_findings
shift
set "NF_ARGS="
:list_loop
if not "%~1"=="" (
    set "NF_ARGS=!NF_ARGS! %1"
    shift
    goto :list_loop
)
python "%NIGHTFANG_ROOT%\tools\findings.py" --list-findings!NF_ARGS!
goto :eof

:run_test
python "%NIGHTFANG_ROOT%\tools\daemon.py" --test
if errorlevel 1 exit /b 1
python "%NIGHTFANG_ROOT%\tools\gateway.py" --test
if errorlevel 1 exit /b 1
python "%NIGHTFANG_ROOT%\schemas\validator.py" --test
if errorlevel 1 exit /b 1
python "%NIGHTFANG_ROOT%\tools\findings.py" --test
if errorlevel 1 exit /b 1
echo.
echo [*] All 3 unified engine self-tests and schema validator passed successfully!
exit /b 0

:run_test_all
python "%NIGHTFANG_ROOT%\tools\daemon.py" --test
if errorlevel 1 exit /b 1
python "%NIGHTFANG_ROOT%\tools\gateway.py" --test
if errorlevel 1 exit /b 1
python "%NIGHTFANG_ROOT%\schemas\validator.py" --test
if errorlevel 1 exit /b 1
python "%NIGHTFANG_ROOT%\tools\findings.py" --test
if errorlevel 1 exit /b 1
python "%NIGHTFANG_ROOT%\tools\simulation.py" --test
if errorlevel 1 exit /b 1
echo.
echo [*] All 3 unified engines and E2E simulation passed successfully!
exit /b 0

