[CmdletBinding()]
param(
    [switch]$RemoveImages
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

Write-Host '[teardown] Removing Phase 15 Compose containers, networks, and volumes'
$Arguments = @(
    'compose',
    '--profile', 'soc',
    '--profile', 'llm',
    '--profile', 'supply-chain',
    'down',
    '--volumes',
    '--remove-orphans'
)
if ($RemoveImages) {
    $Arguments += @('--rmi', 'local')
}
docker @Arguments
if ($LASTEXITCODE) {
    throw 'Phase 15 Compose teardown failed.'
}

$TetragonContainer = docker ps -aq --filter 'name=^/arsl-tetragon$'
if ($TetragonContainer) {
    Write-Host '[teardown] Removing the project Tetragon sensor container'
    docker rm -f arsl-tetragon *> $null
    if ($LASTEXITCODE) {
        throw 'Phase 15 Tetragon sensor teardown failed.'
    }
}

$ProjectFilter = 'label=com.docker.compose.project=agent-runtime-security-lab'
$RemainingContainers = @(docker ps -aq --filter $ProjectFilter | Where-Object { $_ })
$RemainingNetworks = @(docker network ls -q --filter $ProjectFilter | Where-Object { $_ })
$RemainingVolumes = @(docker volume ls -q --filter $ProjectFilter | Where-Object { $_ })
$RemainingTetragon = @(docker ps -aq --filter 'name=^/arsl-tetragon$' | Where-Object { $_ })
if ($RemainingContainers.Count -or $RemainingNetworks.Count -or $RemainingVolumes.Count -or $RemainingTetragon.Count) {
    throw 'Phase 15 teardown left one or more project resources behind.'
}

Write-Host 'Phase 15 teardown passed: project containers, networks, and volumes removed.'
