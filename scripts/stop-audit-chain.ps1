[CmdletBinding()]
param(
    [string]$ClusterName = 'arsl-phase8'
)

$ErrorActionPreference = 'Stop'
if ($ClusterName -notmatch '^arsl-phase8(?:-[a-z0-9-]+)?$') {
    throw 'Refusing to delete a cluster outside the dedicated Phase 8 namespace.'
}

$KnownClusters = @(kind get clusters 2>$null)
if ($ClusterName -notin $KnownClusters) {
    Write-Host "Kind cluster does not exist: $ClusterName"
    exit 0
}

kind delete cluster --name $ClusterName
if ($LASTEXITCODE -ne 0) {
    throw "Could not delete the Phase 8 Kind cluster: $ClusterName"
}
Write-Host "Deleted dedicated Phase 8 Kind cluster: $ClusterName"
