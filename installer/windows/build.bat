@echo off
setlocal enabledelayedexpansion

:: Builds the PwnBroker Windows agent installer end-to-end:
::   1. Installs pyinstaller/pywin32/requests/psutil into whatever Python
::      is on PATH
::   2. Freezes pwnbroker_agent.py into a standalone agent.exe
::   3. Smoke-tests the frozen exe
::   4. Compiles PwnBrokerAgentSetup.exe with Inno Setup
::
:: Usage (from anywhere — this script finds the repo root itself):
::   build.bat            (version defaults to 0.0.0-dev)
::   build.bat 1.2.3       (stamps that version on the installer)
::
:: Prerequisites: Python 3.12 x64 on PATH, Inno Setup 6 installed
:: (https://jrsoftware.org/isdl.php, or `choco install innosetup -y`).
::
:: Output: dist\installer\PwnBrokerAgentSetup.exe (relative to repo root)
:: Copy that file to app\static\agent\PwnBrokerAgentSetup.exe on the
:: server — the app serves it from there, it never reaches out to GitHub.

set "VERSION=%~1"
if "%VERSION%"=="" set "VERSION=0.0.0-dev"

:: Resolve repo root as two levels up from this script's own location
:: (installer\windows\build.bat -> repo root), regardless of the caller's
:: current directory.
set "SCRIPT_DIR=%~dp0"
pushd "%SCRIPT_DIR%..\.." || (echo [FAIL] Could not resolve repo root & exit /b 1)
set "REPO_ROOT=%CD%"
echo [INFO] Repo root: %REPO_ROOT%
echo [INFO] Version  : %VERSION%
echo.

:: ── Step 1: Python ─────────────────────────────────────────────────────────
echo [1/5] Checking for Python...
where python >nul 2>&1
if errorlevel 1 (
    echo [FAIL] Python not found on PATH. Install Python 3.12 x64 from
    echo        https://python.org, check "Add to PATH" during install, then
    echo        re-run this script.
    popd
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo [INFO]   %%v

:: ── Step 2: Build dependencies ────────────────────────────────────────────
echo.
echo [2/5] Installing build dependencies (pyinstaller, pywin32, requests, psutil)...
python -m pip install --quiet --upgrade pip
if errorlevel 1 (
    echo [FAIL] pip self-upgrade failed.
    popd
    exit /b 1
)
python -m pip install --quiet pyinstaller pywin32 requests psutil
if errorlevel 1 (
    echo [FAIL] Failed to install build dependencies.
    popd
    exit /b 1
)

:: ── Step 3: Freeze agent.py ───────────────────────────────────────────────
echo.
echo [3/5] Freezing pwnbroker_agent.py with PyInstaller...
if exist "%REPO_ROOT%\build\pwnbroker_agent" rmdir /s /q "%REPO_ROOT%\build\pwnbroker_agent"
if exist "%REPO_ROOT%\dist\pwnbroker_agent" rmdir /s /q "%REPO_ROOT%\dist\pwnbroker_agent"
python -m PyInstaller --noconfirm installer\windows\pwnbroker_agent.spec
if errorlevel 1 (
    echo [FAIL] PyInstaller build failed.
    popd
    exit /b 1
)
if not exist "%REPO_ROOT%\dist\pwnbroker_agent\pwnbroker_agent.exe" (
    echo [FAIL] Expected output not found: dist\pwnbroker_agent\pwnbroker_agent.exe
    popd
    exit /b 1
)

echo [INFO] Smoke-testing the frozen exe...
"%REPO_ROOT%\dist\pwnbroker_agent\pwnbroker_agent.exe" --help >nul 2>&1
if errorlevel 1 (
    echo [FAIL] pwnbroker_agent.exe --help exited non-zero — the frozen build is broken.
    popd
    exit /b 1
)
echo [INFO]   OK

:: ── Step 4: Locate Inno Setup ─────────────────────────────────────────────
echo.
echo [4/5] Locating Inno Setup (ISCC.exe)...
set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not defined ISCC if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if not defined ISCC (
    where ISCC.exe >nul 2>&1 && set "ISCC=ISCC.exe"
)
if not defined ISCC (
    echo [FAIL] Inno Setup not found. Install it from https://jrsoftware.org/isdl.php
    echo        (or `choco install innosetup -y`^), then re-run this script.
    popd
    exit /b 1
)
echo [INFO]   Found: %ISCC%

:: ── Step 5: Compile the installer ─────────────────────────────────────────
echo.
echo [5/5] Compiling PwnBrokerAgentSetup.exe...
"%ISCC%" "/DMyAppVersion=%VERSION%" installer\windows\pwnbroker_agent.iss
if errorlevel 1 (
    echo [FAIL] Inno Setup compilation failed.
    popd
    exit /b 1
)
if not exist "%REPO_ROOT%\dist\installer\PwnBrokerAgentSetup.exe" (
    echo [FAIL] Expected output not found: dist\installer\PwnBrokerAgentSetup.exe
    popd
    exit /b 1
)

echo.
echo === Build complete ===
echo Installer: %REPO_ROOT%\dist\installer\PwnBrokerAgentSetup.exe
echo.
echo Next step: copy that file to app\static\agent\PwnBrokerAgentSetup.exe
echo on whichever machine actually serves the app.

popd
endlocal
exit /b 0
