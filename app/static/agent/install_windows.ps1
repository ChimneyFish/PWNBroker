#Requires -RunAsAdministrator
<#
.SYNOPSIS
    PwnBroker Agent — Enterprise Installer
.DESCRIPTION
    Installs the PwnBroker agent as a Windows Service.
    Compatible with Intune Win32 App deployment and GPO Computer Startup Scripts.

    Intune:
      Install cmd  : powershell.exe -ExecutionPolicy Bypass -NonInteractive -File install_windows.ps1
      Uninstall cmd: powershell.exe -ExecutionPolicy Bypass -NonInteractive -File install_windows.ps1 -Uninstall
      Detection    : Registry key HKLM\SOFTWARE\PwnBroker\Agent, value "Version" exists

    GPO:
      Computer Configuration > Windows Settings > Scripts > Startup
      Add this script as a PowerShell startup script.
#>
param(
    [switch]$Uninstall,
    [switch]$NoVerifySsl
)

$ErrorActionPreference = "Stop"

# ── Baked-in configuration ────────────────────────────────────────────────────
$Server   = "__PWNBROKER_SERVER__"
$RegToken = "__REG_TOKEN__"

# ── Paths & constants ─────────────────────────────────────────────────────────
$InstallDir  = "$env:ProgramFiles\PwnBroker"
$DataDir     = "$env:ProgramData\PwnBroker"
$AgentScript = "$InstallDir\agent.py"
$VenvDir     = "$InstallDir\venv"
$VenvPy      = "$VenvDir\Scripts\python.exe"
$VenvPip     = "$VenvDir\Scripts\pip.exe"
$ServiceName = "PwnBrokerAgent"
$RegPath     = "HKLM:\SOFTWARE\PwnBroker\Agent"
$Version     = "1.0"

# ── Logging ───────────────────────────────────────────────────────────────────
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$LogFile = "$DataDir\install.log"

function Log {
    param([string]$Msg, [string]$Level = "INFO")
    $line = "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [$Level] $Msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

function Die {
    param([string]$Msg)
    Log $Msg "ERROR"
    exit 1
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
if ($Uninstall) {
    Log "=== PwnBroker Agent Uninstall ==="

    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc) {
        Log "Stopping service..."
        if ($svc.Status -eq "Running") {
            Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
            Start-Sleep -Seconds 2
        }
        if (Test-Path $VenvPy) {
            Log "Removing service registration..."
            & $VenvPy $AgentScript remove 2>&1 | ForEach-Object { Log $_ }
        } else {
            sc.exe delete $ServiceName | Out-Null
        }
    }

    if (Test-Path $InstallDir) {
        Log "Removing install directory..."
        Remove-Item -Recurse -Force $InstallDir -ErrorAction SilentlyContinue
    }
    if (Test-Path $DataDir) {
        Log "Removing data directory..."
        Remove-Item -Recurse -Force $DataDir -ErrorAction SilentlyContinue
    }
    if (Test-Path $RegPath) {
        Remove-Item -Recurse -Force $RegPath -ErrorAction SilentlyContinue
    }

    Log "Uninstall complete."
    exit 0
}

# ── Install ───────────────────────────────────────────────────────────────────
Log "=== PwnBroker Agent Installation ==="
Log "Server     : $Server"
Log "InstallDir : $InstallDir"

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null

# ── Step 1: Python ────────────────────────────────────────────────────────────
Log "[1/5] Locating Python 3..."
$PythonExe = $null

foreach ($cmd in @("python", "python3", "py")) {
    try {
        $ver = & $cmd --version 2>&1
        if ($LASTEXITCODE -eq 0 -and "$ver" -match "Python 3") {
            $PythonExe = (Get-Command $cmd -ErrorAction SilentlyContinue).Source
            Log "  Found: $PythonExe  ($ver)"
            break
        }
    } catch {}
}

if (-not $PythonExe) {
    Log "  Python not found. Attempting silent install via winget..."
    try {
        $proc = Start-Process -FilePath "winget" `
            -ArgumentList "install --id Python.Python.3.12 --silent --accept-source-agreements --accept-package-agreements" `
            -Wait -PassThru -NoNewWindow
        if ($proc.ExitCode -ne 0) { throw "winget exit $($proc.ExitCode)" }
        # Refresh PATH
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
        $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
        Log "  Python installed via winget."
    } catch {
        Log "  winget failed: $_" "WARN"
    }
}

if (-not $PythonExe) {
    Log "  winget unavailable. Downloading Python 3.12 installer..."
    $PyInstaller = "$env:TEMP\python-installer.exe"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.4/python-3.12.4-amd64.exe" `
                          -OutFile $PyInstaller -UseBasicParsing
        $proc = Start-Process -FilePath $PyInstaller `
            -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" `
            -Wait -PassThru
        Remove-Item $PyInstaller -Force -ErrorAction SilentlyContinue
        if ($proc.ExitCode -ne 0) { throw "Python installer exit $($proc.ExitCode)" }
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" +
                    [System.Environment]::GetEnvironmentVariable("PATH","User")
        $PythonExe = (Get-Command python -ErrorAction SilentlyContinue).Source
        Log "  Python installed from python.org."
    } catch {
        Die "Failed to install Python: $_"
    }
}

if (-not $PythonExe) { Die "Python 3 could not be located after install attempts." }

# ── Step 2: Virtual environment ───────────────────────────────────────────────
Log "[2/5] Creating virtual environment at $VenvDir..."
if (Test-Path $VenvDir) { Remove-Item -Recurse -Force $VenvDir }
& $PythonExe -m venv $VenvDir 2>&1 | ForEach-Object { Log "  $_" }
if (-not (Test-Path $VenvPy)) { Die "venv creation failed." }

Log "  Installing dependencies (requests, psutil, pywin32)..."
& $VenvPip install --quiet --upgrade pip 2>&1 | Out-Null
& $VenvPip install --quiet requests psutil pywin32 2>&1 | Out-Null

# pywin32 post-install — registers COM DLLs and pythonservice.exe
$PostInstall = "$VenvDir\Scripts\pywin32_postinstall.py"
if (Test-Path $PostInstall) {
    Log "  Running pywin32 post-install..."
    & $VenvPy $PostInstall -install 2>&1 | ForEach-Object { Log "  $_" }
}
Log "  Dependencies ready."

# ── Step 3: Write agent script ────────────────────────────────────────────────
Log "[3/5] Writing agent.py to $InstallDir..."
$AgentContent = @'
__AGENT_CONTENT__
'@
[System.IO.File]::WriteAllText($AgentScript, $AgentContent, [System.Text.Encoding]::UTF8)
Log "  agent.py written."

# ── Step 4: Register agent with server ───────────────────────────────────────
Log "[4/5] Registering with $Server..."
$RegArgs = @($AgentScript, "--server", $Server, "--reg-token", $RegToken, "--register")
if ($NoVerifySsl) { $RegArgs += "--no-verify-ssl" }

$proc = Start-Process -FilePath $VenvPy -ArgumentList $RegArgs `
    -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$DataDir\reg_out.txt" `
    -RedirectStandardError "$DataDir\reg_err.txt"
Get-Content "$DataDir\reg_out.txt" -ErrorAction SilentlyContinue | ForEach-Object { Log "  $_" }
Get-Content "$DataDir\reg_err.txt" -ErrorAction SilentlyContinue | ForEach-Object { Log "  [stderr] $_" }
if ($proc.ExitCode -ne 0) { Die "Registration failed (exit $($proc.ExitCode)). Check server URL and token." }
Log "  Registration successful."

# ── Step 5: Windows Service ───────────────────────────────────────────────────
Log "[5/5] Installing Windows Service '$ServiceName'..."

# Remove existing service cleanly
$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Log "  Removing existing service..."
    if ($existing.Status -eq "Running") {
        Stop-Service -Name $ServiceName -Force
        Start-Sleep -Seconds 2
    }
    & $VenvPy $AgentScript remove 2>&1 | ForEach-Object { Log "  $_" }
    Start-Sleep -Seconds 1
}

# Install via pywin32 HandleCommandLine
$proc = Start-Process -FilePath $VenvPy -ArgumentList @($AgentScript, "install") `
    -Wait -PassThru -NoNewWindow -RedirectStandardOutput "$DataDir\svc_out.txt" `
    -RedirectStandardError "$DataDir\svc_err.txt"
Get-Content "$DataDir\svc_out.txt" -ErrorAction SilentlyContinue | ForEach-Object { Log "  $_" }
Get-Content "$DataDir\svc_err.txt" -ErrorAction SilentlyContinue | ForEach-Object { Log "  [stderr] $_" }
if ($proc.ExitCode -ne 0) { Die "Service install failed (exit $($proc.ExitCode))." }

# Configure: automatic start, restart on failure (5s / 10s / 30s)
sc.exe config   $ServiceName start= auto | Out-Null
sc.exe failure  $ServiceName reset= 86400 actions= restart/5000/restart/10000/restart/30000 | Out-Null
sc.exe description $ServiceName "PwnBroker security monitoring agent" | Out-Null

Log "  Starting service..."
Start-Service -Name $ServiceName
Start-Sleep -Seconds 3

$svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne "Running") {
    Die "Service failed to start. Check $DataDir\install.log and Windows Event Log."
}
Log "  Service is running."

# ── Detection registry key ────────────────────────────────────────────────────
New-Item  -Path $RegPath -Force | Out-Null
Set-ItemProperty -Path $RegPath -Name "Version"     -Value $Version     -Type String
Set-ItemProperty -Path $RegPath -Name "InstallDir"  -Value $InstallDir  -Type String
Set-ItemProperty -Path $RegPath -Name "Server"      -Value $Server      -Type String
Set-ItemProperty -Path $RegPath -Name "InstalledAt" -Value (Get-Date -Format "o") -Type String
Log "  Registry detection key written: $RegPath"

# ── Done ──────────────────────────────────────────────────────────────────────
Log ""
Log "=== Installation Complete ==="
Log "Service '$ServiceName' is running and set to start automatically."
Log ""
Log "Intune detection rule:"
Log "  Type  : Registry"
Log "  Key   : HKEY_LOCAL_MACHINE\SOFTWARE\PwnBroker\Agent"
Log "  Value : Version"
Log "  Check : Key exists"
Log ""
Log "Useful commands:"
Log "  Get-Service $ServiceName"
Log "  Stop-Service $ServiceName"
Log "  Start-Service $ServiceName"
Log "  Uninstall: powershell -File install_windows.ps1 -Uninstall"
exit 0
