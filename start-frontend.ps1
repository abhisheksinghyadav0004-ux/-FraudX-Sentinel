$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$frontendRoot = Join-Path $projectRoot "frontend"
$port = 5173
$listener = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue | Select-Object -First 1

if ($listener) {
    Write-Host "Frontend already appears to be running at http://localhost:$port" -ForegroundColor Yellow
    return
}

if (-not (Test-Path (Join-Path $frontendRoot "node_modules"))) {
    Write-Host "Installing frontend dependencies..." -ForegroundColor Yellow
    Push-Location $frontendRoot
    npm install
    Pop-Location
}

Write-Host "Starting FraudX Sentinel frontend at http://localhost:$port" -ForegroundColor Green
Push-Location $frontendRoot
npm run dev
Pop-Location
