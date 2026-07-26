[CmdletBinding()]
param(
    [string]$EvidencePath = 'docs\evidence\phase12-mcp-supply-chain.json',
    [int]$RegistryPort = 15000,
    [string]$ServiceHost = '127.0.0.1'
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot
$RuntimeRoot = Join-Path $LabRoot 'runtime\phase12'
$ToolsRoot = Join-Path $RuntimeRoot 'tools'
$ManifestPath = Join-Path $LabRoot 'deploy\supply-chain\trusted-mcp-tools.json'
$ToolManifestType = 'https://agent-runtime-security.dev/attestations/mcp-tool-manifest/v1'
$CosignVersion = '3.1.2'
$SyftVersion = '1.49.0'
$CosignAsset = 'cosign-windows-amd64.exe'
$SyftAsset = "syft_${SyftVersion}_windows_amd64.zip"
$Cosign = Join-Path $ToolsRoot 'cosign.exe'
$Syft = Join-Path $ToolsRoot 'syft.exe'
$Registry = "${ServiceHost}:$RegistryPort"
$TrustedTag = "$Registry/arsl/mcp-server:phase12"

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

function Invoke-OpaDecision {
    param([hashtable]$InputObject)
    $Body = @{ input = $InputObject } | ConvertTo-Json -Depth 10 -Compress
    return (Invoke-RestMethod -Method Post -Uri "http://$ServiceHost`:8181/v1/data/supply_chain/decision" -ContentType 'application/json' -Body $Body -TimeoutSec 30).result
}

function Invoke-QuietNative {
    param([scriptblock]$Command)
    $PreviousPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $Command *> $null
        return $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $PreviousPreference
    }
}

function Invoke-Gate {
    param([string]$Image)
    $Output = python -m supply_chain.gate `
        --image $Image `
        --manifest $ManifestPath `
        --public-key "$KeyPrefix.pub" `
        --cosign $Cosign `
        --docker docker `
        --allow-insecure-registry `
        --offline-verification
    $Code = $LASTEXITCODE
    if ($Code -notin @(0, 2)) { throw "Supply-chain gate failed unexpectedly for $Image." }
    return [ordered]@{ exit_code = $Code; payload = ($Output | ConvertFrom-Json) }
}

Write-Host '[1/9] Checking Docker and preparing verified tools on D: drive'
$PreviousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
docker info *> $null
$DockerReady = $LASTEXITCODE -eq 0
$ErrorActionPreference = $PreviousErrorAction
if (-not $DockerReady) { throw 'Docker Desktop is not running.' }
New-Item -ItemType Directory -Path $ToolsRoot -Force | Out-Null

$CosignHash = Get-VerifiedReleaseAsset `
    -AssetUrl "https://github.com/sigstore/cosign/releases/download/v$CosignVersion/$CosignAsset" `
    -AssetName $CosignAsset `
    -ChecksumUrl "https://github.com/sigstore/cosign/releases/download/v$CosignVersion/cosign_checksums.txt" `
    -Destination $Cosign
$SyftZip = Join-Path $ToolsRoot $SyftAsset
$SyftZipHash = Get-VerifiedReleaseAsset `
    -AssetUrl "https://github.com/anchore/syft/releases/download/v$SyftVersion/$SyftAsset" `
    -AssetName $SyftAsset `
    -ChecksumUrl "https://github.com/anchore/syft/releases/download/v$SyftVersion/syft_${SyftVersion}_checksums.txt" `
    -Destination $SyftZip
Expand-Archive -LiteralPath $SyftZip -DestinationPath $ToolsRoot -Force
if (-not (Test-Path -LiteralPath $Syft)) { throw 'Syft executable was not extracted.' }

Write-Host '[2/9] Starting the loopback-only OCI registry and OPA'
$env:ARSL_REGISTRY_PORT = [string]$RegistryPort
$env:ARSL_BIND_ADDRESS = $ServiceHost
if ($ServiceHost -ne '127.0.0.1') {
    $resolvedRoot = [System.IO.Path]::GetFullPath($LabRoot)
    if ($resolvedRoot -notmatch '^([A-Za-z]):\\(.*)$') {
        throw 'Unable to resolve the WSL project path.'
    }
    $drive = $Matches[1].ToLowerInvariant()
    $relative = $Matches[2].Replace('\', '/')
    $env:ARSL_PROJECT_ROOT = "/mnt/$drive/$relative"
}
docker compose --profile supply-chain up -d registry
if ($LASTEXITCODE) { throw 'Supply-chain registry failed to start.' }
docker compose --profile supply-chain up -d --force-recreate opa
if ($LASTEXITCODE) { throw 'Supply-chain services failed to start.' }
$Deadline = (Get-Date).AddMinutes(2)
do {
    Start-Sleep -Seconds 2
    try {
        $RegistryReady = (Invoke-WebRequest -UseBasicParsing "http://$Registry/v2/" -TimeoutSec 3).StatusCode -eq 200
    } catch {
        $RegistryReady = $false
    }
} while (-not $RegistryReady -and (Get-Date) -lt $Deadline)
if (-not $RegistryReady) { throw 'Local OCI registry did not become ready.' }

Write-Host '[3/9] Building and pushing the trusted MCP server'
$ManifestHash = python -c "from pathlib import Path; from supply_chain.gate import canonical_manifest_sha256, load_manifest; print(canonical_manifest_sha256(load_manifest(Path(r'$ManifestPath'))))"
if ($LASTEXITCODE -or $ManifestHash -notmatch '^[a-f0-9]{64}$') { throw 'Tool manifest fingerprint failed.' }
docker build --build-arg "ARSL_TOOL_MANIFEST_SHA256=$ManifestHash" -t $TrustedTag mcp-server
if ($LASTEXITCODE) { throw 'Trusted MCP image build failed.' }
docker push $TrustedTag
if ($LASTEXITCODE) { throw 'Trusted MCP image push failed.' }
$TrustedPinned = (docker image inspect --format '{{index .RepoDigests 0}}' $TrustedTag).Trim()
if ($TrustedPinned -notmatch '@sha256:[a-f0-9]{64}$') { throw 'Trusted image digest was not resolved.' }
$TrustedDigest = ($TrustedPinned -split '@')[1]

Write-Host '[4/9] Generating an ephemeral signing key and CycloneDX SBOM'
$KeyPrefix = Join-Path $RuntimeRoot 'cosign'
$SigningConfig = Join-Path $RuntimeRoot 'offline-signing-config.json'
foreach ($Path in @("$KeyPrefix.key", "$KeyPrefix.pub")) {
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
}
$env:COSIGN_PASSWORD = ([guid]::NewGuid().ToString('N')) + ([guid]::NewGuid().ToString('N'))
$NativeExit = Invoke-QuietNative { & $Cosign generate-key-pair --output-key-prefix $KeyPrefix }
if ($NativeExit) { throw 'Cosign key generation failed.' }
$NativeExit = Invoke-QuietNative { & $Cosign signing-config create --out $SigningConfig }
if ($NativeExit -or -not (Test-Path -LiteralPath $SigningConfig)) { throw 'Offline signing config generation failed.' }
$SbomPath = Join-Path $RuntimeRoot 'trusted-mcp.cdx.json'
$NativeExit = Invoke-QuietNative { & $Syft $TrustedTag --from docker --output "cyclonedx-json=$SbomPath" }
if ($NativeExit -or -not (Test-Path -LiteralPath $SbomPath)) { throw 'CycloneDX SBOM generation failed.' }
$Sbom = Get-Content -Raw $SbomPath | ConvertFrom-Json
$SbomHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $SbomPath).Hash.ToLowerInvariant()
$SbomComponentCount = @($Sbom.components).Count

Write-Host '[5/9] Signing the image and attaching the SBOM attestation'
$NativeExit = Invoke-QuietNative { & $Cosign sign --yes --key "$KeyPrefix.key" --signing-config $SigningConfig --allow-insecure-registry $TrustedPinned }
if ($NativeExit) { throw 'Trusted image signing failed.' }
$NativeExit = Invoke-QuietNative { & $Cosign attest --yes --key "$KeyPrefix.key" --signing-config $SigningConfig --type cyclonedx --predicate $SbomPath --allow-insecure-registry $TrustedPinned }
if ($NativeExit) { throw 'SBOM attestation failed.' }
$NativeExit = Invoke-QuietNative { & $Cosign attest --yes --key "$KeyPrefix.key" --signing-config $SigningConfig --type $ToolManifestType --predicate $ManifestPath --allow-insecure-registry $TrustedPinned }
if ($NativeExit) { throw 'Tool-manifest attestation failed.' }
$PublicKeyFingerprint = (Get-FileHash -Algorithm SHA256 -LiteralPath "$KeyPrefix.pub").Hash.ToLowerInvariant()

Write-Host '[6/9] Allowing only the signed digest through the gate and OPA'
$TrustedGate = Invoke-Gate $TrustedPinned
if ($TrustedGate.exit_code -ne 0 -or $TrustedGate.payload.result -ne 'passed') { throw 'Trusted image was not admitted.' }
$TrustedPolicy = Invoke-OpaDecision @{
    signature_verified = [bool]$TrustedGate.payload.controls.signature_verified
    digest_pinned = [bool]$TrustedGate.payload.controls.digest_pinned
    sbom_attestation_verified = [bool]$TrustedGate.payload.controls.sbom_attestation_verified
    tool_manifest_verified = [bool]$TrustedGate.payload.controls.tool_manifest_verified
}
if (-not $TrustedPolicy.allow) { throw 'OPA denied the trusted image.' }
$NativeExit = Invoke-QuietNative { docker run --rm --entrypoint python $TrustedPinned -c "import app.main; print('trusted MCP import passed')" }
if ($NativeExit) { throw 'Admitted MCP image failed its import smoke test.' }

Write-Host '[7/9] Replacing the mutable tag with an unsigned tool-drift image'
docker build --build-arg "TRUSTED_BASE=$TrustedPinned" -f supply_chain/fixtures/Malicious.Dockerfile -t $TrustedTag .
if ($LASTEXITCODE) { throw 'Tampered MCP image build failed.' }
docker push $TrustedTag
if ($LASTEXITCODE) { throw 'Tampered MCP image push failed.' }
$TamperedPinned = (docker image inspect --format '{{index .RepoDigests 0}}' $TrustedTag).Trim()
if ($TamperedPinned -notmatch '@sha256:[a-f0-9]{64}$') { throw 'Tampered image digest was not resolved.' }
$UnsignedGate = Invoke-Gate $TamperedPinned
if ($UnsignedGate.exit_code -ne 2 -or $UnsignedGate.payload.reason_code -ne 'signature_verification_failed') {
    throw 'Unsigned image was not blocked by signature verification.'
}
$MutableGate = Invoke-Gate $TrustedTag
if ($MutableGate.exit_code -ne 2 -or $MutableGate.payload.reason_code -ne 'unpinned_image_reference') {
    throw 'Mutable image tag was not blocked.'
}

Write-Host '[8/9] Signing the drifted image to test manifest defense in depth'
$TamperedSbomPath = Join-Path $RuntimeRoot 'tampered-mcp.cdx.json'
$NativeExit = Invoke-QuietNative { & $Syft $TrustedTag --from docker --output "cyclonedx-json=$TamperedSbomPath" }
if ($NativeExit) { throw 'Tampered image SBOM generation failed.' }
$NativeExit = Invoke-QuietNative { & $Cosign sign --yes --key "$KeyPrefix.key" --signing-config $SigningConfig --allow-insecure-registry $TamperedPinned }
if ($NativeExit) { throw 'Tampered test-image signing failed.' }
$NativeExit = Invoke-QuietNative { & $Cosign attest --yes --key "$KeyPrefix.key" --signing-config $SigningConfig --type cyclonedx --predicate $TamperedSbomPath --allow-insecure-registry $TamperedPinned }
if ($NativeExit) { throw 'Tampered test-image attestation failed.' }
$NativeExit = Invoke-QuietNative { & $Cosign attest --yes --key "$KeyPrefix.key" --signing-config $SigningConfig --type $ToolManifestType --predicate $ManifestPath --allow-insecure-registry $TamperedPinned }
if ($NativeExit) { throw 'Tampered test-image tool-manifest attestation failed.' }
$DriftGate = Invoke-Gate $TamperedPinned
if ($DriftGate.exit_code -ne 2 -or $DriftGate.payload.reason_code -ne 'tool_manifest_digest_mismatch') {
    throw 'Signed tool-manifest drift was not blocked.'
}
$NativeExit = Invoke-QuietNative { docker pull $TrustedPinned }
if ($NativeExit) { throw 'Trusted pinned digest could not be restored.' }
$PinnedReplay = Invoke-Gate $TrustedPinned
if ($PinnedReplay.exit_code -ne 0) { throw 'Trusted pinned digest failed after tag replacement.' }

Write-Host '[9/9] Verifying OPA fail-closed decisions and exporting evidence'
$UnsignedPolicy = Invoke-OpaDecision @{
    signature_verified = $false; digest_pinned = $true; sbom_attestation_verified = $false; tool_manifest_verified = $false
}
$MutablePolicy = Invoke-OpaDecision @{
    signature_verified = $true; digest_pinned = $false; sbom_attestation_verified = $true; tool_manifest_verified = $true
}
$DriftPolicy = Invoke-OpaDecision @{
    signature_verified = $true; digest_pinned = $true; sbom_attestation_verified = $true; tool_manifest_verified = $false
}
if ($UnsignedPolicy.allow -or $MutablePolicy.allow -or $DriftPolicy.allow) { throw 'OPA supply-chain policy failed open.' }

$Checks = [ordered]@{
    release_tool_checksums_verified = $CosignHash.Length -eq 64 -and $SyftZipHash.Length -eq 64
    trusted_signature_verified = $TrustedGate.payload.controls.signature_verified
    image_digest_pinned = $TrustedGate.payload.controls.digest_pinned
    cyclonedx_sbom_attested = $TrustedGate.payload.controls.sbom_attestation_verified
    tool_manifest_bound_to_image = $TrustedGate.payload.controls.tool_manifest_verified
    trusted_image_admitted = $TrustedPolicy.allow -and $PinnedReplay.payload.result -eq 'passed'
    unsigned_image_blocked = -not $UnsignedPolicy.allow
    mutable_tag_blocked = -not $MutablePolicy.allow
    signed_tool_drift_blocked = -not $DriftPolicy.allow
    malicious_container_never_started = $true
}
$Evidence = [ordered]@{
    phase = 12
    result = if (@($Checks.Values | Where-Object { -not $_ }).Count -eq 0) { 'passed' } else { 'failed' }
    tools = [ordered]@{ cosign = "v$CosignVersion"; syft = "v$SyftVersion"; checksums_verified = $true }
    trusted_artifact = [ordered]@{
        image = 'local-registry/arsl/mcp-server'
        digest = $TrustedDigest
        signer_public_key_sha256 = $PublicKeyFingerprint
        tool_manifest_sha256 = $ManifestHash
        sbom = [ordered]@{ format = 'CycloneDX JSON'; sha256 = $SbomHash; component_count = $SbomComponentCount }
        decision = 'allow'
    }
    attack_replay = @(
        [ordered]@{ scenario = 'unsigned_image_replacement'; decision = 'deny'; reason_code = $UnsignedGate.payload.reason_code; executed = $false },
        [ordered]@{ scenario = 'mutable_tag_reference'; decision = 'deny'; reason_code = $MutableGate.payload.reason_code; executed = $false },
        [ordered]@{ scenario = 'signed_tool_manifest_drift'; decision = 'deny'; reason_code = $DriftGate.payload.reason_code; executed = $false }
    )
    privacy = [ordered]@{ private_key_exported = $false; signing_password_exported = $false; raw_signature_exported = $false; sbom_package_paths_exported = $false }
    checks = $Checks
}
if ($Evidence.result -ne 'passed') { throw 'One or more Phase 12 checks failed.' }
$ResolvedEvidence = Join-Path $LabRoot $EvidencePath
$Parent = Split-Path -Parent $ResolvedEvidence
if (-not (Test-Path $Parent)) { New-Item -ItemType Directory -Path $Parent -Force | Out-Null }
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($ResolvedEvidence, ($Evidence | ConvertTo-Json -Depth 20), $Utf8NoBom)
$Evidence
