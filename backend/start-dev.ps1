<#
.SYNOPSIS
Starts FastAPI and Vite using the shared project-root .env configuration.
#>

$projectRoot = $PSScriptRoot
$envFile = Join-Path $projectRoot '.env'

if (-not (Test-Path -LiteralPath $envFile)) {
    throw 'Missing project root .env file.'
}

$values = @{}
Get-Content -LiteralPath $envFile | ForEach-Object {
    if ($_ -match '^\s*([A-Z][A-Z0-9_]*)\s*=\s*(.*?)\s*$') {
        $values[$matches[1]] = $matches[2].Trim('"')
    }
}

$backendHost = $values['BACKEND_HOST']
$backendPort = $values['BACKEND_PORT']
if (-not $backendHost -or -not $backendPort) {
    throw 'BACKEND_HOST and BACKEND_PORT must be set in the project root .env file.'
}

$python = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw 'Missing .venv. Create it and install requirements before running start-dev.ps1.'
}

Start-Process -FilePath $python -ArgumentList @('-m', 'uvicorn', 'backend.app.main:app', '--reload', '--host', $backendHost, '--port', $backendPort, '--loop', 'asyncio', '--http', 'h11') -WorkingDirectory $projectRoot -WindowStyle Hidden


Write-Host "Started FastAPI at http://$backendHost`:$backendPort and Vite with a proxy target from .env."
