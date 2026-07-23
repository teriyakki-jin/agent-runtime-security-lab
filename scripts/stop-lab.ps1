[CmdletBinding()]
param(
    [switch]$RemoveImages
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

if ($RemoveImages) {
    docker compose down --rmi local
} else {
    docker compose down
}

if ($LASTEXITCODE -ne 0) {
    throw 'Docker Compose shutdown failed.'
}
