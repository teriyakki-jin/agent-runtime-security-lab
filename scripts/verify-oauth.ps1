[CmdletBinding()]
param(
    [string]$OutputPath = ""
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

$Result = docker compose exec -T agent-api python -m app.oauth_lab
if ($LASTEXITCODE -ne 0) {
    throw 'Phase 9 OAuth validation failed.'
}

$Parsed = $Result | ConvertFrom-Json
if ($Parsed.result -ne 'passed') {
    throw 'Phase 9 OAuth validation did not pass every control.'
}

if ($OutputPath) {
    $ResolvedOutput = Join-Path $LabRoot $OutputPath
    $Parent = Split-Path -Parent $ResolvedOutput
    if (-not (Test-Path $Parent)) {
        New-Item -ItemType Directory -Path $Parent -Force | Out-Null
    }
    $EvidenceJson = $Parsed | ConvertTo-Json -Depth 10
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText($ResolvedOutput, $EvidenceJson, $Utf8NoBom)
}

$Parsed
