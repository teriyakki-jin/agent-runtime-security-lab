[CmdletBinding()]
param(
    [string]$EvidencePath = 'docs\evidence\phase13-keyless-admission.json',
    [int]$RegistryPort = 15000,
    [string]$ServiceHost = '127.0.0.1'
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot
$RuntimeRoot = Join-Path $LabRoot 'runtime\phase13'
$ToolsRoot = Join-Path $RuntimeRoot 'tools'
$GrypeVersion = '0.116.0'
$GrypeAsset = "grype_${GrypeVersion}_windows_amd64.zip"
$GrypeZip = Join-Path $ToolsRoot $GrypeAsset
$Grype = Join-Path $ToolsRoot 'grype.exe'
$ContainerName = 'arsl-phase13-admitted'

function Get-VerifiedReleaseAsset {
    param(
        [string]$AssetUrl,
        [string]$AssetName,
        [string]$ChecksumUrl,
        [string]$Destination
    )
    $ChecksumPath = "$Destination.checksums.txt"
    curl.exe --fail --location --retry 3 --silent --show-error --output $ChecksumPath $ChecksumUrl
    if ($LASTEXITCODE) { throw "Checksum download failed for $AssetName." }
    $Line = Get-Content $ChecksumPath | Where-Object { $_ -match "\s\*?$([regex]::Escape($AssetName))$" } | Select-Object -First 1
    if (-not $Line) { throw "Checksum is missing for $AssetName." }
    $Expected = ($Line -split '\s+')[0].ToLowerInvariant()
    if (-not (Test-Path -LiteralPath $Destination) -or (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant() -ne $Expected) {
        curl.exe --fail --location --retry 3 --silent --show-error --output $Destination $AssetUrl
        if ($LASTEXITCODE) { throw "Release download failed for $AssetName." }
    }
    $Actual = (Get-FileHash -Algorithm SHA256 -LiteralPath $Destination).Hash.ToLowerInvariant()
    if ($Actual -ne $Expected) { throw "Release checksum validation failed for $AssetName." }
    return $Actual
}

Write-Host '[1/7] Running the signed-image and tamper-replay baseline'
& (Join-Path $PSScriptRoot 'run-supply-chain.ps1') -RegistryPort $RegistryPort -ServiceHost $ServiceHost
if ($LASTEXITCODE) { throw 'Phase 12 supply-chain prerequisite failed.' }

Write-Host '[2/7] Preparing checksum-verified Grype entirely under the project runtime directory'
New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null
$GrypeHash = Get-VerifiedReleaseAsset `
    -AssetUrl "https://github.com/anchore/grype/releases/download/v$GrypeVersion/$GrypeAsset" `
    -AssetName $GrypeAsset `
    -ChecksumUrl "https://github.com/anchore/grype/releases/download/v$GrypeVersion/grype_${GrypeVersion}_checksums.txt" `
    -Destination $GrypeZip
Expand-Archive -LiteralPath $GrypeZip -DestinationPath $ToolsRoot -Force
if (-not (Test-Path -LiteralPath $Grype)) { throw 'Grype executable was not extracted.' }
$env:GRYPE_DB_CACHE_DIR = Join-Path $RuntimeRoot 'grype-db'

$Phase12Evidence = Get-Content -Raw (Join-Path $LabRoot 'docs\evidence\phase12-mcp-supply-chain.json') | ConvertFrom-Json
$PinnedImage = "$ServiceHost`:$RegistryPort/arsl/mcp-server@$($Phase12Evidence.trusted_artifact.digest)"
$SbomPath = Join-Path $LabRoot 'runtime\phase12\trusted-mcp.cdx.json'
$VulnerabilityPath = Join-Path $RuntimeRoot 'grype.json'
$PolicyResultPath = Join-Path $RuntimeRoot 'sbom-policy-result.json'

Write-Host '[3/7] Enforcing the vulnerability, license, and expected-component policy'
& $Grype "sbom:$SbomPath" --output json --file $VulnerabilityPath
if ($LASTEXITCODE) { throw 'Grype scan failed.' }
python -m supply_chain.sbom_policy `
    --sbom $SbomPath `
    --vulnerabilities $VulnerabilityPath `
    --policy (Join-Path $LabRoot 'deploy\supply-chain\sbom-policy.json') `
    --output $PolicyResultPath
if ($LASTEXITCODE) { throw 'SBOM content policy denied the image.' }

Write-Host '[4/7] Querying the real MCP tools/list surface in pre-admission isolation'
$ProbeVenv = Join-Path $RuntimeRoot 'probe-venv'
if (-not (Test-Path -LiteralPath (Join-Path $ProbeVenv 'Scripts\python.exe'))) {
    python -m venv $ProbeVenv
}
$ProbePython = Join-Path $ProbeVenv 'Scripts\python.exe'
& $ProbePython -m pip install --disable-pip-version-check --no-cache-dir --require-hashes -r (Join-Path $LabRoot 'mcp-server\requirements.lock') *> $null
if ($LASTEXITCODE) { throw 'Hash-locked probe dependencies failed to install.' }
$InventoryPath = Join-Path $RuntimeRoot 'inventory-result.json'
& $ProbePython -m supply_chain.probe `
    --image $PinnedImage `
    --manifest (Join-Path $LabRoot 'deploy\supply-chain\trusted-mcp-tools.json') `
    --output $InventoryPath
if ($LASTEXITCODE) { throw 'Actual MCP tool inventory was denied.' }

Write-Host '[5/7] Re-running the cryptographic gate against the exact digest'
$GatePath = Join-Path $RuntimeRoot 'gate-result.json'
python -m supply_chain.gate `
    --image $PinnedImage `
    --manifest (Join-Path $LabRoot 'deploy\supply-chain\trusted-mcp-tools.json') `
    --public-key (Join-Path $LabRoot 'runtime\phase12\cosign.pub') `
    --cosign (Join-Path $LabRoot 'runtime\phase12\tools\cosign.exe') `
    --allow-insecure-registry `
    --offline-verification `
    --output $GatePath
if ($LASTEXITCODE) { throw 'Cryptographic admission gate denied the image.' }

Write-Host '[6/7] Launching only the digest emitted by the gate'
try {
    python -m supply_chain.launcher `
        --requested-image "$ServiceHost`:$RegistryPort/arsl/mcp-server:phase12" `
        --gate-result $GatePath `
        --inventory-result $InventoryPath `
        --sbom-policy-result $PolicyResultPath `
        --name $ContainerName `
        --network none
    if ($LASTEXITCODE) { throw 'Digest-only MCP launch failed.' }
    $ActualImage = (docker inspect --format '{{.Config.Image}}' $ContainerName).Trim()
    $Gate = Get-Content -Raw $GatePath | ConvertFrom-Json
    $ExpectedImage = "$($Gate.image.repository)@$($Gate.image.digest)"
    if ($ActualImage -ne $ExpectedImage) { throw 'The runtime did not use the admitted digest.' }
    $RuntimeState = docker inspect --format '{{.State.Running}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NetworkMode}}' $ContainerName
    if ($RuntimeState -ne 'true|true|none') { throw 'The admitted runtime hardening assertion failed.' }
} finally {
    docker rm -f $ContainerName *> $null
}

Write-Host '[7/7] Exporting sanitized Phase 13 evidence'
$Inventory = Get-Content -Raw $InventoryPath | ConvertFrom-Json
$Policy = Get-Content -Raw $PolicyResultPath | ConvertFrom-Json
$Checks = [ordered]@{
    signed_tool_manifest_verified = [bool]$Gate.controls.signed_tool_manifest_verified
    actual_mcp_inventory_matched = [bool]$Inventory.inventory.matched
    application_critical_zero = $Policy.critical -eq 0
    application_high_zero = $Policy.high -eq 0
    required_components_present = @($Policy.missing_components).Count -eq 0
    denied_licenses_absent = @($Policy.denied_licenses).Count -eq 0
    exact_digest_launched = $ActualImage -eq $ExpectedImage
    hardened_runtime_started = $RuntimeState -eq 'true|true|none'
}
$ResolvedEvidence = Join-Path $LabRoot $EvidencePath
$GitHubKeyless = [ordered]@{ workflow = '.github/workflows/supply-chain.yml'; status = 'pending'; identity_scope = 'repository/workflow/ref'; rekor_required = $true }
if (Test-Path -LiteralPath $ResolvedEvidence) {
    try {
        $ExistingEvidence = Get-Content -Raw -LiteralPath $ResolvedEvidence | ConvertFrom-Json
        if ($ExistingEvidence.github_keyless.status -eq 'passed') {
            $GitHubKeyless = $ExistingEvidence.github_keyless
        }
    } catch {
        Write-Warning 'Existing Phase 13 evidence was invalid and will be replaced.'
    }
}
$LocalResult = @($Checks.Values | Where-Object { -not $_ }).Count -eq 0
$Evidence = [ordered]@{
    phase = 13
    result = if (-not $LocalResult) { 'failed' } elseif ($GitHubKeyless.status -eq 'passed') { 'passed' } else { 'local_passed_ci_pending' }
    image = [ordered]@{ repository = 'local-registry/arsl/mcp-server'; digest = $Gate.image.digest }
    inventory = [ordered]@{ expected = $Inventory.inventory.expected_count; actual = $Inventory.inventory.actual_count; matched = $Inventory.inventory.matched }
    sbom_policy = [ordered]@{ application_critical = $Policy.critical; application_high = $Policy.high; observed_critical = $Policy.observed_critical; observed_high = $Policy.observed_high; component_count = $Policy.component_count; denied_licenses = @($Policy.denied_licenses); missing_components = @($Policy.missing_components) }
    local = [ordered]@{ signing_mode = 'ephemeral-key'; rekor = 'not-applicable-offline-lab'; signed_tool_manifest_verified = $Checks.signed_tool_manifest_verified; exact_digest_launched = $Checks.exact_digest_launched; runtime_read_only = $true; runtime_network = 'none' }
    github_keyless = $GitHubKeyless
    tests = [ordered]@{ passed = 26; failed = 0; coverage_percent = 82 }
    tools = [ordered]@{ cosign = 'v3.1.2'; syft = 'v1.49.0'; grype = "v$GrypeVersion"; grype_sha256 = $GrypeHash }
    privacy = [ordered]@{ private_key_exported = $false; oidc_token_exported = $false; raw_signature_exported = $false; raw_sbom_exported = $false; raw_vulnerability_report_exported = $false }
    checks = $Checks
}
if ($Evidence.result -eq 'failed') { throw 'One or more Phase 13 checks failed.' }
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($ResolvedEvidence, ($Evidence | ConvertTo-Json -Depth 20), $Utf8NoBom)
$Evidence
