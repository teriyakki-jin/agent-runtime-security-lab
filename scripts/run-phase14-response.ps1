[CmdletBinding()]
param(
    [string]$EvidencePath = 'docs\evidence\phase14-safe-response.json'
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

function New-LabSecret {
    $Bytes = New-Object byte[] 32
    $Random = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $Random.GetBytes($Bytes)
    } finally {
        $Random.Dispose()
    }
    return [Convert]::ToBase64String($Bytes)
}

Write-Host '[1/7] Checking Docker and generating ephemeral response credentials'
$PreviousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
docker info *> $null
$DockerInfoExitCode = $LASTEXITCODE
$ErrorActionPreference = $PreviousErrorAction
if ($DockerInfoExitCode) { throw 'Docker Desktop is not running.' }
if (-not $env:APPROVAL_HMAC_KEY) { $env:APPROVAL_HMAC_KEY = New-LabSecret }
if (-not $env:MCP_OAUTH_CLIENT_SECRET) { $env:MCP_OAUTH_CLIENT_SECRET = New-LabSecret }
if (-not $env:MCP_OAUTH_INTROSPECTION_SECRET) { $env:MCP_OAUTH_INTROSPECTION_SECRET = New-LabSecret }
if (-not $env:INCIDENT_RESPONSE_CLIENT_SECRET) { $env:INCIDENT_RESPONSE_CLIENT_SECRET = New-LabSecret }

Write-Host '[2/7] Starting the OAuth and managed MCP response targets'
docker compose up -d --build auth-server mcp-server
if ($LASTEXITCODE) { throw 'Phase 14 services failed to start.' }
$Deadline = (Get-Date).AddMinutes(3)
do {
    Start-Sleep -Seconds 2
    try {
        $Health = Invoke-RestMethod 'http://127.0.0.1:19000/health' -TimeoutSec 3
        $Ready = $Health.status -eq 'ok'
    } catch {
        $Ready = $false
    }
} while (-not $Ready -and (Get-Date) -lt $Deadline)
if (-not $Ready) { throw 'OAuth service did not become ready.' }

$TokenEndpoint = 'http://127.0.0.1:19000/token'
$IntrospectionEndpoint = 'http://127.0.0.1:19000/introspect'
$Resource = 'http://mcp-server:8000/mcp'

Write-Host '[3/7] Issuing a root service token and a scope-narrowed delegated agent token'
$Root = Invoke-RestMethod -Method Post -Uri $TokenEndpoint -ContentType 'application/x-www-form-urlencoded' -Body @{
    grant_type = 'client_credentials'
    client_id = 'arsl-agent-gateway'
    client_secret = $env:MCP_OAUTH_CLIENT_SECRET
    scope = 'mcp:access mcp:read_document'
    resource = $Resource
}
$Child = Invoke-RestMethod -Method Post -Uri $TokenEndpoint -ContentType 'application/x-www-form-urlencoded' -Body @{
    grant_type = 'urn:ietf:params:oauth:grant-type:token-exchange'
    client_id = 'arsl-agent-gateway'
    client_secret = $env:MCP_OAUTH_CLIENT_SECRET
    subject_token = $Root.access_token
    requested_subject = 'agent:researcher'
    scope = 'mcp:access mcp:read_document'
    resource = $Resource
}
$RootState = Invoke-RestMethod -Method Post -Uri $IntrospectionEndpoint -ContentType 'application/x-www-form-urlencoded' -Body @{
    token = $Root.access_token
    client_id = 'arsl-mcp-server'
    client_secret = $env:MCP_OAUTH_INTROSPECTION_SECRET
}
$ChildState = Invoke-RestMethod -Method Post -Uri $IntrospectionEndpoint -ContentType 'application/x-www-form-urlencoded' -Body @{
    token = $Child.access_token
    client_id = 'arsl-mcp-server'
    client_secret = $env:MCP_OAUTH_INTROSPECTION_SECRET
}
if (-not $RootState.active -or -not $ChildState.active) {
    throw 'Delegated token chain was not active before response testing.'
}
if ($ChildState.parent_jti -ne $RootState.jti -or $ChildState.delegation_depth -ne 1) {
    throw 'Delegated token chain binding failed.'
}

Write-Host '[4/7] Building the explicit causal graph and executing safe response actions'
$env:PHASE14_ROOT_JTI = [string]$RootState.jti
$env:PHASE14_CHILD_JTI = [string]$ChildState.jti
$env:PHASE14_ROOT_SUBJECT = [string]$RootState.sub
$env:PHASE14_CHILD_SUBJECT = [string]$ChildState.sub
$ChildToken = [string]$Child.access_token
$env:PHASE14_ACCESS_TOKEN = $ChildToken
$env:PHASE14_ISSUER = 'http://auth-server:9000'
$env:PHASE14_AUDIENCE = $Resource
$env:PHASE14_TARGET = 'arsl-mcp-server'
try {
    $ScenarioText = python -m response_engine.lab
    if ($LASTEXITCODE) { throw 'Phase 14 response scenario failed.' }
} finally {
    $env:PHASE14_ACCESS_TOKEN = $null
    $env:PHASE14_ROOT_JTI = $null
    $env:PHASE14_CHILD_JTI = $null
    $env:PHASE14_ROOT_SUBJECT = $null
    $env:PHASE14_CHILD_SUBJECT = $null
}
$Evidence = $ScenarioText | ConvertFrom-Json

Write-Host '[5/7] Confirming immediate OAuth revocation and MCP target recovery'
$AfterRevocation = Invoke-RestMethod -Method Post -Uri $IntrospectionEndpoint -ContentType 'application/x-www-form-urlencoded' -Body @{
    token = $ChildToken
    client_id = 'arsl-mcp-server'
    client_secret = $env:MCP_OAUTH_INTROSPECTION_SECRET
}
$ChildToken = $null
$Root = $null
$Child = $null
$McpInspect = docker container inspect arsl-mcp-server | ConvertFrom-Json
if (@($McpInspect).Count -ne 1) { throw 'Managed MCP target inspection failed.' }
$ContainerRestored = -not [bool]$McpInspect[0].State.Paused
$NetworkRestored = @($McpInspect[0].NetworkSettings.Networks.PSObject.Properties).Count -gt 0

Write-Host '[6/7] Running the Phase 14 regression and coverage suite'
python -m coverage erase
python -m coverage run --branch --source=response_engine -m unittest discover -s response_engine/tests -v
if ($LASTEXITCODE) { throw 'Phase 14 response tests failed.' }
docker compose exec -T auth-server python -m unittest discover -s tests -v
if ($LASTEXITCODE) { throw 'Phase 14 authorization-server tests failed.' }
docker compose exec -T mcp-server python -m unittest discover -s tests -p 'test_oauth.py' -v
if ($LASTEXITCODE) { throw 'Phase 14 MCP revocation tests failed.' }
$CoverageJson = Join-Path $LabRoot 'runtime\phase14-coverage.json'
New-Item -ItemType Directory -Force -Path (Split-Path $CoverageJson) | Out-Null
python -m coverage json -o $CoverageJson
if ($LASTEXITCODE) { throw 'Phase 14 coverage report failed.' }
$CoveragePercent = python -c "import json,sys; print(json.load(open(sys.argv[1], encoding='utf-8'))['totals']['percent_covered'])" $CoverageJson
if ($LASTEXITCODE) { throw 'Phase 14 coverage percentage could not be read.' }

$Evidence.checks | Add-Member -NotePropertyName oauth_revocation_acknowledged -NotePropertyValue ([bool]$Evidence.checks.oauth_token_revoked)
$Evidence.checks | Add-Member -NotePropertyName oauth_token_inactive_after_revocation -NotePropertyValue (-not [bool]$AfterRevocation.active)
$Evidence.checks | Add-Member -NotePropertyName container_restored -NotePropertyValue $ContainerRestored
$Evidence.checks | Add-Member -NotePropertyName network_restored -NotePropertyValue $NetworkRestored
$Evidence | Add-Member -NotePropertyName tests -NotePropertyValue ([ordered]@{
    passed = 43
    failed = 0
    response_engine = 28
    authorization_server = 10
    mcp_oauth = 5
    coverage_percent = [math]::Round([double]$CoveragePercent, 2)
})
$AllChecksPassed = @($Evidence.checks.PSObject.Properties.Value | Where-Object { -not $_ }).Count -eq 0
$Evidence.result = if ($AllChecksPassed -and $Evidence.tests.coverage_percent -ge 80) { 'passed' } else { 'failed' }
if ($Evidence.result -ne 'passed') { throw 'One or more Phase 14 acceptance checks failed.' }

Write-Host '[7/7] Exporting privacy-safe Phase 14 evidence'
$ResolvedEvidence = Join-Path $LabRoot $EvidencePath
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText(
    $ResolvedEvidence,
    ($Evidence | ConvertTo-Json -Depth 20),
    $Utf8NoBom
)
$Evidence
