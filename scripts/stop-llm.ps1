[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

docker compose --profile llm stop local-llm
if ($LASTEXITCODE -ne 0) {
    throw 'Failed to stop the local llama.cpp lab service.'
}

Write-Host 'Local LLM stopped. The model cache volume is retained for replay.'
