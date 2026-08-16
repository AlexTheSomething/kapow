@echo off
setlocal enabledelayedexpansion
title Kapow - Network Auditor
echo.
echo    ========================================
echo      Kapow Network Auditor v1.5
echo      Starting desktop application...
echo    ========================================
echo.

REM --- Find Python ---
set PYTHON=
for %%p in (python py python3) do (
    where %%p >nul 2>&1
    if !errorlevel!==0 (
        for /f "delims=" %%v in ('%%p --version 2^>^&1') do set PYVER=%%v
        echo [INFO] Found %%p - !PYVER!
        set PYTHON=%%p
        goto :found_python
    )
)
echo [ERROR] Python 3.10+ not found. Install from https://python.org/downloads/
pause
exit /b 1

:found_python

REM --- Check Node.js (for frontend build) ---
where node >nul 2>&1
if %errorlevel% neq 0 (
    echo [WARN] Node.js not found. Frontend will not auto-build.
    echo        Install Node.js: https://nodejs.org/ or pre-build with: cd frontend ^&^& npm run build
)

REM --- Check/install Python dependencies ---
%PYTHON% -c "import webview" >nul 2>&1
if !errorlevel! neq 0 (
    echo [INFO] Installing Python dependencies...
    %PYTHON% -m pip install -r requirements.txt --quiet
    if !errorlevel! neq 0 (
        echo [ERROR] Failed to install Python dependencies.
        pause
        exit /b 1
    )
)

REM --- Check/rebuild frontend if needed ---
set DIST=frontend\dist\index.html
if not exist "%DIST%" (
    echo [INFO] Production frontend bundle (frontend\dist) not found.
    where npm.cmd >nul 2>&1
    if !errorlevel! neq 0 (
        echo [ERROR] Node.js/npm is required to build the frontend.
        echo        Build manually: cd frontend ^&^& npm install ^&^& npm run build
        pause
        exit /b 1
    )
    echo [INFO] Building frontend (this may take 1-2 minutes)...
    cd frontend
    call npm.cmd install --silent 2>nul
    echo [INFO] Running Vite production build...
    call npm.cmd run build
    cd ..
    if not exist "frontend\dist\index.html" (
        echo [ERROR] Frontend build failed.
        pause
        exit /b 1
    )
    echo [INFO] Frontend build complete.
)

REM --- Launch Kapow in production mode ---
echo.
echo [INFO] Launching Kapow desktop GUI...
echo.
%PYTHON% main.py --prod

REM --- If the window closed abnormally, keep the console open ---
if %errorlevel% neq 0 (
    echo.
    echo [WARN] Kapow exited with code %errorlevel%.
    pause
)