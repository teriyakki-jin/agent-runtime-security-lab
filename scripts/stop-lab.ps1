[CmdletBinding()]
param(
    [switch]$RemoveImages
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

if ($RemoveImages) {
    docker compose --profile soc down --rmi local
} else {
    docker compose --profile soc down
}

if ($LASTEXITCODE -ne 0) {
    throw 'Docker Compose shutdown failed.'
}
