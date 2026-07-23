[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

Write-Host '[1/4] Checking Docker engine'
& cmd.exe /d /c 'docker info >nul 2>&1'
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Desktop is not running.'
}

Write-Host '[2/4] Building and starting the lab'
docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Compose startup failed.'
}

Write-Host '[3/4] Waiting for OPA and the agent gateway'
$Deadline = (Get-Date).AddMinutes(3)
$Ready = $false
do {
    Start-Sleep -Seconds 3
    try {
        $Opa = Invoke-RestMethod 'http://127.0.0.1:8181/health?plugins' -TimeoutSec 3
        $Agent = Invoke-RestMethod 'http://127.0.0.1:8080/health' -TimeoutSec 3
        $Ready = $Agent.status -eq 'ok'
    } catch {
        $Ready = $false
    }
} while (-not $Ready -and (Get-Date) -lt $Deadline)

if (-not $Ready) {
    throw 'The lab did not become ready within 3 minutes.'
}

Write-Host '[4/4] Running security verification'
& (Join-Path $PSScriptRoot 'verify-lab.ps1')

Write-Host 'Agent API : http://127.0.0.1:8080/docs'
Write-Host 'Jaeger UI : http://127.0.0.1:16686'
Write-Host 'OPA API   : http://127.0.0.1:8181'
