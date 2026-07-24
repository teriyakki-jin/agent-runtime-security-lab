[CmdletBinding(SupportsShouldProcess)]
param(
    [string]$ClusterName = 'arsl-phase7'
)

$ErrorActionPreference = 'Stop'
if ($ClusterName -notmatch '^arsl-phase7(?:-[a-z0-9-]+)?$') {
    throw 'Refusing to delete a cluster outside the arsl-phase7 naming boundary.'
}
$PreviousPreference = $ErrorActionPreference
$ErrorActionPreference = 'SilentlyContinue'
$ExistingClusters = @(kind get clusters 2>$null)
$ErrorActionPreference = $PreviousPreference
if ($ClusterName -notin $ExistingClusters) {
    Write-Host "Kind cluster is already absent: $ClusterName"
    return
}
if ($PSCmdlet.ShouldProcess($ClusterName, 'Delete dedicated Kind cluster')) {
    kind delete cluster --name $ClusterName
    if ($LASTEXITCODE -ne 0) { throw 'Kind cluster deletion failed.' }
}
