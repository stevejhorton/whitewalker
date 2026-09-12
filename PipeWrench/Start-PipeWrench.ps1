$ErrorActionPreference = 'Stop'
$ProjectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ProjectRoot

$Python = Get-Command py -ErrorAction SilentlyContinue
if ($Python) {
    Start-Process 'http://127.0.0.1:8765'
    & py -3 server.py
    exit $LASTEXITCODE
}

$Python = Get-Command python -ErrorAction SilentlyContinue
if (-not $Python) {
    Write-Error 'Python 3 was not found. Install Python 3 or add it to PATH.'
}

Start-Process 'http://127.0.0.1:8765'
& python server.py
