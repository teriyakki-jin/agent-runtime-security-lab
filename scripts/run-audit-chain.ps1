[CmdletBinding()]
param(
    [switch]$Recreate,
    [string]$ClusterName = 'arsl-phase8'
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot
$RuntimeRoot = Join-Path $LabRoot 'runtime/phase8'
$AuditRoot = Join-Path $RuntimeRoot 'audit'
$Helm = Join-Path $LabRoot 'runtime/tools/windows-amd64/helm.exe'
$BundledKubectl = Join-Path $LabRoot 'runtime/tools/kubectl.exe'
$Kubectl = if (Test-Path -LiteralPath $BundledKubectl) {
    $BundledKubectl
} else {
    (Get-Command 'kubectl' -ErrorAction Stop).Source
}
$Context = "kind-$ClusterName"
$Attacker = 'system:serviceaccount:arsl-lab:compromised-agent'

if ($ClusterName -notmatch '^arsl-phase8(?:-[a-z0-9-]+)?$') {
    throw 'ClusterName must be a dedicated arsl-phase8 cluster name.'
}
if (-not (Test-Path -LiteralPath $Helm)) {
    throw 'Helm is missing under runtime/tools/windows-amd64.'
}

foreach ($Directory in @($RuntimeRoot, $AuditRoot)) {
    New-Item -ItemType Directory -Force -Path $Directory | Out-Null
}
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
    Write-Host "Removing the dedicated Phase 8 Kind cluster: $ClusterName"
    kind delete cluster --name $ClusterName
    if ($LASTEXITCODE -ne 0) { throw 'Could not remove the Phase 8 Kind cluster.' }
    $ClusterExists = $false
}

Write-Host '[1/9] Preparing the audit-enabled Kind cluster'
if (-not $ClusterExists) {
    kind create cluster `
        --name $ClusterName `
        --config deploy/kind/phase8-cluster.yaml `
        --wait 180s
    if ($LASTEXITCODE -ne 0) { throw 'Audit-enabled Kind cluster creation failed.' }
}
& $Kubectl config use-context $Context | Out-Null

Write-Host '[2/9] Installing Tetragon 1.7.0'
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

Write-Host '[3/9] Applying the intentionally vulnerable RBAC lab boundary'
& $Kubectl --context $Context apply -f deploy/kubernetes/phase8-rbac-bootstrap.yaml
if ($LASTEXITCODE -ne 0) { throw 'Phase 8 RBAC bootstrap failed.' }

Write-Host '[4/9] Resetting only the replayable attack objects'
& $Kubectl --context $Context delete pod audit-shadow -n arsl-lab --ignore-not-found --wait=true
if ($LASTEXITCODE -ne 0) { throw 'Could not reset the Phase 8 attack Pod.' }
& $Kubectl --context $Context delete rolebinding shadow-cluster-admin -n arsl-lab --ignore-not-found
if ($LASTEXITCODE -ne 0) { throw 'Could not reset the Phase 8 escalation RoleBinding.' }

Write-Host '[5/9] Replaying ServiceAccount RBAC escalation and Pod deployment'
& $Kubectl --context $Context --as=$Attacker create -f deploy/kubernetes/phase8-escalation.yaml
if ($LASTEXITCODE -ne 0) { throw 'The compromised identity could not create the escalation binding.' }
& $Kubectl --context $Context --as=$Attacker create -f deploy/kubernetes/phase8-shadow-pod.yaml
if ($LASTEXITCODE -ne 0) { throw 'The escalated identity could not create the shadow Pod.' }
& $Kubectl --context $Context wait -n arsl-lab --for=condition=Ready pod/audit-shadow --timeout=180s
if ($LASTEXITCODE -ne 0) { throw 'The Phase 8 shadow Pod did not become ready.' }

Write-Host '[6/9] Generating an identity-bound runtime execution event'
& $Kubectl --context $Context --as=$Attacker exec -n arsl-lab audit-shadow -c tool -- /bin/echo phase8-rbac-chain | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'The escalated identity could not execute in the shadow Pod.' }
# Tetragon's event cache may wait up to 30 seconds for Kubernetes metadata.
Start-Sleep -Seconds 35

Write-Host '[7/9] Capturing Pod inventory and Tetragon evidence'
$InventoryPath = Join-Path $RuntimeRoot 'pod-inventory.json'
$Inventory = & $Kubectl --context $Context get pods -n arsl-lab -o json
if ($LASTEXITCODE -ne 0) { throw 'Could not read the Phase 8 Pod inventory.' }
$Inventory | Set-Content -LiteralPath $InventoryPath -Encoding UTF8
$TetragonPath = Join-Path $RuntimeRoot 'tetragon-events.jsonl'
$Tetragon = & $Kubectl --context $Context logs `
    -n kube-system `
    -l app.kubernetes.io/name=tetragon `
    -c export-stdout `
    --tail=5000
if ($LASTEXITCODE -ne 0) { throw 'Could not export Phase 8 Tetragon events.' }
$Tetragon | Set-Content -LiteralPath $TetragonPath -Encoding UTF8

Write-Host '[8/9] Reading Kubernetes API audit evidence'
$AuditPath = Join-Path $AuditRoot 'kube-apiserver-audit.log'
if (-not (Test-Path -LiteralPath $AuditPath)) {
    throw "Kubernetes audit log was not created: $AuditPath"
}

Write-Host '[9/9] Correlating RBAC, Pod, exec, and kernel events'
$ResultPath = Join-Path $RuntimeRoot 'audit-chain-validation.json'
python kubernetes/audit_chain.py `
    --audit $AuditPath `
    --inventory $InventoryPath `
    --tetragon $TetragonPath `
    --cluster $ClusterName `
    --output $ResultPath
if ($LASTEXITCODE -ne 0) { throw 'Kubernetes audit attack-chain verification failed.' }

Write-Host 'Phase 8 Kubernetes audit/RBAC attack-chain verification passed.'
Write-Host "Cluster context: $Context"
Write-Host "Evidence: $ResultPath"
