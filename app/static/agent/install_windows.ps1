# PwnBroker Agent Installer — Windows (Task Scheduler)
# Run in PowerShell as Administrator
# Usage: .\install_windows.ps1 [-NoVerifySsl]
param(
    [switch]$NoVerifySsl
)

$Server   = "__PWNBROKER_SERVER__"
$RegToken = "__REG_TOKEN__"
$AgentDir = "$env:APPDATA\PwnBroker"
$VenvDir  = "$AgentDir\venv"
$TaskName = "PwnBrokerAgent"

Write-Host "=== PwnBroker Agent Installer (Windows) ===" -ForegroundColor Cyan
Write-Host "Server : $Server"
Write-Host ""

# Check Python
$python = $null
foreach ($candidate in @("python", "python3", "py")) {
    try {
        $ver = & $candidate --version 2>&1
        if ($LASTEXITCODE -eq 0) { $python = $candidate; break }
    } catch {}
}
if (-not $python) {
    Write-Error "Python not found. Install from https://www.python.org/downloads/ and add to PATH."
    exit 1
}
Write-Host "Using: $python ($( & $python --version 2>&1 ))"

# Create venv
Write-Host "[1/4] Setting up virtual environment at $VenvDir..."
New-Item -ItemType Directory -Force -Path $AgentDir | Out-Null
& $python -m venv $VenvDir
$VenvPy  = "$VenvDir\Scripts\python.exe"
$VenvPip = "$VenvDir\Scripts\pip.exe"
& $VenvPip install --quiet --upgrade pip | Out-Null
& $VenvPip install --quiet requests psutil
Write-Host "    requests + psutil installed."

# Write agent script (embedded — no separate download required)
Write-Host "[2/4] Writing agent to $AgentDir\agent.py..."
$agentContent = @'
__AGENT_CONTENT__
'@
[System.IO.File]::WriteAllText("$AgentDir\agent.py", $agentContent, [System.Text.Encoding]::UTF8)

# Register
Write-Host "[3/4] Registering agent with $Server..."
$regArgs = @(
    "$AgentDir\agent.py",
    "--server", $Server,
    "--reg-token", $RegToken,
    "--register"
)
if ($NoVerifySsl) { $regArgs += "--no-verify-ssl" }
& $VenvPy @regArgs
if ($LASTEXITCODE -ne 0) {
    Write-Error "Registration failed."
    exit 1
}

# Create scheduled task
Write-Host "[4/4] Creating scheduled task '$TaskName'..."
$extraArg = if ($NoVerifySsl) { " --no-verify-ssl" } else { "" }
$taskArgs  = "`"$AgentDir\agent.py`"$extraArg"

$action   = New-ScheduledTaskAction -Execute $VenvPy -Argument $taskArgs
$trigger  = New-ScheduledTaskTrigger -AtStartup
$settings = New-ScheduledTaskSettingsSet `
    -ExecutionTimeLimit ([TimeSpan]::Zero) `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 1)

Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Register-ScheduledTask `
    -TaskName $TaskName `
    -Action   $action  `
    -Trigger  $trigger `
    -Settings $settings `
    -RunLevel Highest  `
    -Force | Out-Null

Start-ScheduledTask -TaskName $TaskName

Write-Host ""
Write-Host "=== Done! ===" -ForegroundColor Green
Write-Host "Agent installed as scheduled task '$TaskName'"
Write-Host "To check : Get-ScheduledTask -TaskName '$TaskName'"
Write-Host "To stop  : Stop-ScheduledTask  -TaskName '$TaskName'"
