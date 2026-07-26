[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

Write-Host '[1/4] Checking Docker engine'
$PreviousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
docker info *> $null
$DockerInfoExitCode = $LASTEXITCODE
$ErrorActionPreference = $PreviousErrorAction
if ($DockerInfoExitCode -ne 0) {
    throw 'Docker Desktop is not running.'
}

Write-Host '[2/4] Building and starting the lab'
if (-not $env:APPROVAL_HMAC_KEY) {
    $KeyBytes = New-Object byte[] 32
    $Random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Random.GetBytes($KeyBytes)
    } finally {
        $Random.Dispose()
    }
    $env:APPROVAL_HMAC_KEY = [Convert]::ToBase64String($KeyBytes)
}
if (-not $env:RUNTIME_SENSOR_HMAC_KEY) {
    $SensorKeyBytes = New-Object byte[] 32
    $SensorRandom = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $SensorRandom.GetBytes($SensorKeyBytes)
    } finally {
        $SensorRandom.Dispose()
    }
    $env:RUNTIME_SENSOR_HMAC_KEY = [Convert]::ToBase64String($SensorKeyBytes)
}
if (-not $env:MCP_OAUTH_CLIENT_SECRET) {
    $OAuthSecretBytes = New-Object byte[] 32
    $OAuthRandom = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $OAuthRandom.GetBytes($OAuthSecretBytes)
    } finally {
        $OAuthRandom.Dispose()
    }
    $env:MCP_OAUTH_CLIENT_SECRET = [Convert]::ToBase64String($OAuthSecretBytes)
}
if (-not $env:MCP_OAUTH_INTROSPECTION_SECRET) {
    $IntrospectionBytes = New-Object byte[] 32
    $IntrospectionRandom = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $IntrospectionRandom.GetBytes($IntrospectionBytes)
    } finally {
        $IntrospectionRandom.Dispose()
    }
    $env:MCP_OAUTH_INTROSPECTION_SECRET = [Convert]::ToBase64String($IntrospectionBytes)
}
if (-not $env:INCIDENT_RESPONSE_CLIENT_SECRET) {
    $ResponseSecretBytes = New-Object byte[] 32
    $ResponseRandom = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $ResponseRandom.GetBytes($ResponseSecretBytes)
    } finally {
        $ResponseRandom.Dispose()
    }
    $env:INCIDENT_RESPONSE_CLIENT_SECRET = [Convert]::ToBase64String($ResponseSecretBytes)
}
docker compose up -d --build
if ($LASTEXITCODE -ne 0) {
    throw 'Docker Compose startup failed.'
}

Write-Host '[3/4] Waiting for OPA, OAuth, and the agent gateway'
$Deadline = (Get-Date).AddMinutes(3)
$Ready = $false
do {
    Start-Sleep -Seconds 3
    try {
        $Opa = Invoke-RestMethod 'http://127.0.0.1:8181/health?plugins' -TimeoutSec 3
        $OAuth = Invoke-RestMethod 'http://127.0.0.1:19000/health' -TimeoutSec 3
        $Agent = Invoke-RestMethod 'http://127.0.0.1:8080/health' -TimeoutSec 3
        $Ready = $Agent.status -eq 'ok' -and $OAuth.status -eq 'ok'
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
Write-Host 'OAuth AS  : http://127.0.0.1:19000'
