[CmdletBinding()]
param(
    [switch]$Recreate,
    [string]$ClusterName = 'arsl-phase7'
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot
$RuntimeRoot = Join-Path $LabRoot 'runtime/phase7'
$Helm = Join-Path $LabRoot 'runtime/tools/windows-amd64/helm.exe'
$BundledKubectl = Join-Path $LabRoot 'runtime/tools/kubectl.exe'
$Kubectl = if (Test-Path -LiteralPath $BundledKubectl) {
    $BundledKubectl
} else {
    (Get-Command 'kubectl' -ErrorAction Stop).Source
}
$Context = "kind-$ClusterName"

if (-not (Test-Path -LiteralPath $Helm)) {
    throw 'Helm is missing. Install Helm or place helm.exe under runtime/tools/windows-amd64.'
}

$ContextNames = @(& $Kubectl config get-contexts -o name 2>$null)
$ClusterExists = $Context -in $ContextNames
if ($ClusterExists) {
    $PreviousPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    $Ready = & $Kubectl --context $Context get --raw='/readyz' 2>$null
    $ClusterExists = $LASTEXITCODE -eq 0 -and $Ready -eq 'ok'
    $ErrorActionPreference = $PreviousPreference
}
if ($Recreate -and $ClusterExists) {
    Write-Host "Removing the dedicated Kind cluster: $ClusterName"
    kind delete cluster --name $ClusterName
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove the Phase 7 Kind cluster.' }
    $ClusterExists = $false
}

New-Item -ItemType Directory -Force -Path $RuntimeRoot | Out-Null
$ToolStateRoot = Join-Path $RuntimeRoot 'tool-state'
$TempRoot = Join-Path $RuntimeRoot 'temp'
foreach ($Directory in @($ToolStateRoot, $TempRoot)) {
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
}
$env:HELM_CACHE_HOME = Join-Path $ToolStateRoot 'helm-cache'
$env:HELM_CONFIG_HOME = Join-Path $ToolStateRoot 'helm-config'
$env:HELM_DATA_HOME = Join-Path $ToolStateRoot 'helm-data'
$env:TEMP = $TempRoot
$env:TMP = $TempRoot

Write-Host '[1/7] Preparing the dedicated Kind cluster'
if (-not $ClusterExists) {
    kind create cluster `
        --name $ClusterName `
        --config deploy/kind/phase7-cluster.yaml `
        --wait 180s
    if ($LASTEXITCODE -ne 0) { throw 'Kind cluster creation failed.' }
}
& $Kubectl config use-context $Context | Out-Null

Write-Host '[2/7] Installing Tetragon 1.7.0 with Kubernetes metadata enabled'
& $Helm repo add cilium https://helm.cilium.io --force-update | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not add the Cilium Helm repository.' }
& $Helm repo update | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not update the Cilium Helm repository.' }
& $Helm upgrade --install tetragon cilium/tetragon `
    --version 1.7.0 `
    --namespace kube-system `
    --set tetragon.hostProcPath=/procHost `
    --set tetragon.clusterName=$ClusterName `
    --set tetragon.enableK8sAPI=true `
    --wait `
    --timeout 5m
if ($LASTEXITCODE -ne 0) { throw 'Tetragon Helm deployment failed.' }
& $Kubectl --context $Context rollout status -n kube-system ds/tetragon --timeout=180s
if ($LASTEXITCODE -ne 0) { throw 'Tetragon DaemonSet did not become ready.' }

Write-Host '[3/7] Deploying hardened approved and shadow workloads'
& $Kubectl --context $Context apply -f deploy/kubernetes/phase7-workloads.yaml
if ($LASTEXITCODE -ne 0) { throw 'Phase 7 workload deployment failed.' }
foreach ($Pod in @('approved-tool', 'shadow-runner')) {
    & $Kubectl --context $Context wait -n arsl-lab --for=condition=Ready "pod/$Pod" --timeout=180s
    if ($LASTEXITCODE -ne 0) { throw "Pod did not become ready: $Pod" }
}

Write-Host '[4/7] Capturing immutable Pod UID and ServiceAccount inventory'
$InventoryPath = Join-Path $RuntimeRoot 'pod-inventory.json'
$Inventory = & $Kubectl --context $Context get pods -n arsl-lab -o json
if ($LASTEXITCODE -ne 0) { throw 'Could not read the Kubernetes Pod inventory.' }
$Inventory | Set-Content -LiteralPath $InventoryPath -Encoding UTF8

Write-Host '[5/7] Generating approved and identity-abuse process events'
& $Kubectl --context $Context exec -n arsl-lab approved-tool -c tool -- /bin/echo phase7-approved | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not execute the approved workload marker.' }
& $Kubectl --context $Context exec -n arsl-lab shadow-runner -c tool -- /bin/echo phase7-shadow | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not execute the shadow workload marker.' }
Start-Sleep -Seconds 15

Write-Host '[6/7] Exporting real Tetragon JSON events'
$EventsPath = Join-Path $RuntimeRoot 'tetragon-events.jsonl'
$Events = & $Kubectl --context $Context logs `
    -n kube-system `
    -l app.kubernetes.io/name=tetragon `
    -c export-stdout `
    --since=10m
if ($LASTEXITCODE -ne 0) { throw 'Could not export Tetragon events.' }
$Events | Set-Content -LiteralPath $EventsPath -Encoding UTF8

Write-Host '[7/7] Correlating agent intent with Kubernetes workload identity'
$ResultPath = Join-Path $RuntimeRoot 'identity-validation.json'
python kubernetes/identity_verifier.py `
    --inventory $InventoryPath `
    --events $EventsPath `
    --cluster $ClusterName `
    --output $ResultPath
if ($LASTEXITCODE -ne 0) { throw 'Kubernetes workload identity verification failed.' }

Write-Host 'Phase 7 Kubernetes workload identity verification passed.'
Write-Host "Cluster context: $Context"
Write-Host "Evidence: $ResultPath"
