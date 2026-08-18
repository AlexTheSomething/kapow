@echo off
setlocal enabledelayedexpansion
title Kapow - Network Auditor
cd /d "%~dp0"

echo.
echo ==========================================
echo Kapow v1.5 - Network Auditor
echo ==========================================
echo.

:: ---- Find Python ----
set PYTHON=
for %%p in (python py python3) do (
    where %%p >nul 2>&1
    if !errorlevel!==0 (
        set PYTHON=%%p
        echo [OK] Found Python: %%p
        goto :found_python
    )
)
echo [FAIL] Python 3.10+ not found on PATH.
echo        Install from https://python.org/downloads/
pause
exit /b 1

:found_python

:: ---- Check Python deps ----
%PYTHON% -c "import webview" >nul 2>&1
if !errorlevel! neq 0 (
    echo [SETUP] Installing Python dependencies...
    %PYTHON% -m pip install -r requirements.txt --quiet
    if !errorlevel! neq 0 (
        echo [FAIL] Could not install dependencies.
        pause
        exit /b 1
    )
    echo [OK] Dependencies installed.
)

:: ---- Build frontend (always rebuild so dist is never stale) ----
echo [BUILD] Rebuilding frontend...
where npm.cmd >nul 2>&1
if !errorlevel! neq 0 (
    echo [FAIL] Node.js/npm needed to build the frontend.
    echo        Install Node.js: https://nodejs.org/
    echo    OR  run: cd frontend ^&^& npm install ^&^& npm run build
    pause
    exit /b 1
)
cd frontend
call npm.cmd install --silent 2>nul
call npm.cmd run build
cd ..
if not exist "frontend\dist\index.html" (
    echo [FAIL] Frontend build failed.
    pause
    exit /b 1
)
echo [OK] Frontend build complete.

:: ---- Launch ----
echo.
echo [START] Launching Kapow...
%PYTHON% main.py --prod

:: ---- After close ----
echo.
echo Kapow closed. Press any key to exit.
pause >nul
