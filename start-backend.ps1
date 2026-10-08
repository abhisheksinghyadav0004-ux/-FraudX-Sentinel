$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$port = 8000
$listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1
$fraudxProcesses = @(Get-CimInstance Win32_Process |
    Where-Object { $_.Name -match "^python" -and $_.CommandLine -match "uvicorn.*backend\.main:app|backend\.main:app.*uvicorn" })

if ($listener) {
    try {
        $health = Invoke-RestMethod "http://127.0.0.1:$port/health" -TimeoutSec 4
    } catch {
        $health = $null
    }
    if ($health.service -ne "FraudX Sentinel" -and -not ($fraudxProcesses | Where-Object { $_.ProcessId -eq $listener.OwningProcess -or $_.ParentProcessId -eq $listener.OwningProcess })) {
        throw "Port $port is being used by a different process. Close that process or change the port before starting FraudX."
    }
    Write-Host "Restarting the existing FraudX backend on port $port..." -ForegroundColor Yellow
    $processIds = @($listener.OwningProcess)
    $processIds += Get-CimInstance Win32_Process |
        Where-Object { $_.ParentProcessId -eq $listener.OwningProcess -and $_.Name -match "^python" } |
        Select-Object -ExpandProperty ProcessId
    $processIds += $fraudxProcesses | Select-Object -ExpandProperty ProcessId
    foreach ($processId in ($processIds | Select-Object -Unique)) {
        Stop-Process -Id $processId -Force -ErrorAction SilentlyContinue
    }
    for ($attempt = 0; $attempt -lt 10; $attempt++) {
        if (-not (Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue)) { break }
        Start-Sleep -Milliseconds 400
    }
}

Write-Host "Starting FraudX Sentinel backend at http://127.0.0.1:$port" -ForegroundColor Green
& (Join-Path $projectRoot ".venv\Scripts\python.exe") -m uvicorn backend.main:app --reload --port $port
