[CmdletBinding()]
param(
    [string]$EvidencePath = 'docs\evidence\phase15-portfolio-release.json'
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot
$RuntimeDirectory = Join-Path $LabRoot 'runtime'
$RawPath = Join-Path $RuntimeDirectory 'phase15-raw.json'
$CoveragePath = Join-Path $RuntimeDirectory 'phase15-coverage.json'
$Phase14RuntimeEvidence = Join-Path $RuntimeDirectory 'phase15-phase14-response.json'
New-Item -ItemType Directory -Force -Path $RuntimeDirectory | Out-Null

Write-Host '[1/7] Checking Docker and Phase 15 prerequisites'
$PreviousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
docker info *> $null
$DockerExitCode = $LASTEXITCODE
python -c 'import coverage' *> $null
$CoverageExitCode = $LASTEXITCODE
$ErrorActionPreference = $PreviousErrorAction
if ($DockerExitCode) { throw 'Docker Desktop is not running.' }
if ($CoverageExitCode) { throw 'Python coverage is not installed.' }

$RunFailure = $null
$TeardownFailure = $null
try {
    Write-Host '[2/7] Validating pre-execution, runtime, and post-execution controls'
    & (Join-Path $PSScriptRoot 'run-lab.ps1')

    Write-Host '[3/7] Measuring policy latency, detection quality, and resources'
    python -m portfolio_release.runner collect --output $RawPath
    if ($LASTEXITCODE) { throw 'Phase 15 live benchmark collection failed.' }

    Write-Host '[4/7] Replaying causal detection and safe response'
    & (Join-Path $PSScriptRoot 'run-phase14-response.ps1') -EvidencePath 'runtime\phase15-phase14-response.json'

    Write-Host '[5/7] Running Phase 15 tests and branch coverage'
    python -m coverage erase
    python -m coverage run --branch --source=portfolio_release -m unittest discover -s portfolio_release/tests -v
    if ($LASTEXITCODE) { throw 'Phase 15 portfolio tests failed.' }
    python -m coverage json -o $CoveragePath
    if ($LASTEXITCODE) { throw 'Phase 15 coverage report failed.' }
    $CoveragePercent = [double](python -c "import json,sys; print(json.load(open(sys.argv[1], encoding='utf-8'))['totals']['percent_covered'])" $CoveragePath)
    $TestCount = [int](python -c "import unittest; print(unittest.defaultTestLoader.discover('portfolio_release/tests').countTestCases())")
    if ($CoveragePercent -lt 80) { throw "Phase 15 coverage is below 80%: $CoveragePercent" }

    $Raw = Get-Content -Raw -Encoding utf8 $RawPath | ConvertFrom-Json
    $Phase14 = Get-Content -Raw -Encoding utf8 $Phase14RuntimeEvidence | ConvertFrom-Json
    $Raw.response_mttr_ms = [double]$Phase14.mttr.detect_to_block_ms
    $Raw | Add-Member -NotePropertyName tests -NotePropertyValue ([ordered]@{
        passed = $TestCount
        failed = 0
        coverage_percent = [math]::Round($CoveragePercent, 2)
    })
    $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [IO.File]::WriteAllText($RawPath, ($Raw | ConvertTo-Json -Depth 20), $Utf8NoBom)
} catch {
    $RunFailure = $_
} finally {
    Write-Host '[6/7] Performing complete project teardown'
    try {
        & (Join-Path $PSScriptRoot 'stop-phase15.ps1')
    } catch {
        $TeardownFailure = $_
    }
}

if ($TeardownFailure) {
    if ($RunFailure) {
        throw "Phase 15 execution and teardown both failed. Teardown error: $($TeardownFailure.Exception.Message)"
    }
    throw $TeardownFailure
}
if ($RunFailure) { throw $RunFailure }

Write-Host '[7/7] Finalizing machine-readable portfolio evidence'
$ResolvedEvidence = Join-Path $LabRoot $EvidencePath
python -m portfolio_release.runner finalize --input $RawPath --output $ResolvedEvidence
if ($LASTEXITCODE) { throw 'Phase 15 release evidence failed its acceptance gate.' }
$Evidence = Get-Content -Raw -Encoding utf8 $ResolvedEvidence | ConvertFrom-Json
$Evidence
