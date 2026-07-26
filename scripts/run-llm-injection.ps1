[CmdletBinding()]
param(
    [string]$Model = 'Qwen/Qwen3-0.6B-GGUF:Q8_0',
    [string]$OutputPath = 'docs\evidence\phase10-local-llm-injection.json'
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

Write-Host '[1/5] Checking Docker engine'
$PreviousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
docker info *> $null
$DockerInfoExitCode = $LASTEXITCODE
$ErrorActionPreference = $PreviousErrorAction
if ($DockerInfoExitCode -ne 0) {
    throw 'Docker Desktop is not running.'
}

Write-Host '[2/5] Starting isolated llama.cpp service (first run downloads the model)'
$env:ARSL_LLM_MODEL = $Model
$LlmApiKey = ([guid]::NewGuid().ToString('N')) + ([guid]::NewGuid().ToString('N'))
$env:ARSL_LLM_API_KEY = $LlmApiKey
docker compose --profile llm up -d local-llm
if ($LASTEXITCODE -ne 0) {
    throw 'Local llama.cpp container failed to start.'
}

$Deadline = (Get-Date).AddMinutes(15)
$Ready = $false
do {
    Start-Sleep -Seconds 2
    try {
        $Health = Invoke-RestMethod 'http://127.0.0.1:18081/health' -TimeoutSec 3
        $Ready = $Health.status -eq 'ok'
    } catch {
        $Ready = $false
    }
} while (-not $Ready -and (Get-Date) -lt $Deadline)
if (-not $Ready) {
    docker compose --profile llm logs --tail 100 local-llm
    throw 'Local llama.cpp API did not become ready.'
}

Write-Host "[3/5] Local model ready: $Model"
$ModelHashOutput = docker compose exec -T local-llm /bin/sh -c `
    'find /root/.cache/huggingface/hub -type f -size +100M -exec sha256sum {} \;'
if ($LASTEXITCODE -ne 0 -or -not $ModelHashOutput) {
    throw 'Unable to fingerprint the loaded local model.'
}
$ModelDigest = ($ModelHashOutput | Select-Object -First 1).Split()[0]
if ($ModelDigest -notmatch '^[a-f0-9]{64}$') {
    throw 'The local model fingerprint is invalid.'
}

Write-Host '[4/5] Building the local inference harness'
docker compose build agent-api
if ($LASTEXITCODE -ne 0) {
    throw 'Agent API image build failed.'
}

Write-Host '[5/5] Reproducing and blocking indirect prompt injection'
$Result = docker compose --profile llm run --rm --no-deps `
    -e LLM_URL=http://local-llm:8080 `
    -e LLM_MODEL=$Model `
    -e LLM_MODEL_SHA256=$ModelDigest `
    -e LLM_API_KEY=$LlmApiKey `
    agent-api python -m app.prompt_injection_lab
if ($LASTEXITCODE -ne 0) {
    throw 'Local LLM prompt injection validation failed.'
}
$Parsed = $Result | ConvertFrom-Json
if ($Parsed.result -ne 'passed') {
    throw 'One or more local LLM security checks failed.'
}

$ResolvedOutput = Join-Path $LabRoot $OutputPath
$Parent = Split-Path -Parent $ResolvedOutput
if (-not (Test-Path $Parent)) {
    New-Item -ItemType Directory -Path $Parent -Force | Out-Null
}
$EvidenceJson = $Parsed | ConvertTo-Json -Depth 20
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[System.IO.File]::WriteAllText($ResolvedOutput, $EvidenceJson, $Utf8NoBom)

$Parsed
