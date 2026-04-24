@echo off
rem IllegalBet Scanner - one-command local launcher (Windows)
rem Usage:   run.bat          first run installs deps and starts app
rem          run.bat clean    wipe venv and start fresh

setlocal
cd /d "%~dp0"

if "%1"=="clean" (
    echo Removing .venv...
    rmdir /s /q .venv 2>nul
)

where py >nul 2>nul
if errorlevel 1 (
    where python >nul 2>nul
    if errorlevel 1 (
        echo Python not found. Install Python 3.11+ from https://python.org/downloads
        echo Make sure to check "Add Python to PATH" during installation.
        pause
        exit /b 1
    )
    set "PY=python"
) else (
    set "PY=py -3"
)

if not exist .venv (
    echo Creating virtualenv in .venv\ ...
    %PY% -m venv .venv
)

call .venv\Scripts\activate.bat

if not exist .venv\.deps-installed (
    echo Installing dependencies...
    python -m pip install --upgrade pip
    python -m pip install -r requirements.txt
    echo. > .venv\.deps-installed
) else (
    echo Dependencies already installed.
)

if not defined PORT set PORT=8000

echo.
echo ============================================================
echo   IllegalBet Scanner
echo   Dashboard:   http://localhost:%PORT%
echo   Stop:        Ctrl-C
echo ============================================================
echo.

start "" "http://localhost:%PORT%"
python main.py
