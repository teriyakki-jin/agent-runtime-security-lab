[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot
$ElasticsearchPort = if ($env:ARSL_ELASTICSEARCH_PORT) { $env:ARSL_ELASTICSEARCH_PORT } else { '19200' }
$KibanaPort = if ($env:ARSL_KIBANA_PORT) { $env:ARSL_KIBANA_PORT } else { '15601' }
$ElasticsearchUrl = "http://127.0.0.1:$ElasticsearchPort"
$KibanaUrl = "http://127.0.0.1:$KibanaPort"

Write-Host '[1/5] Checking the Phase 5 SOC stack'
try {
    $Cluster = Invoke-RestMethod "$ElasticsearchUrl/_cluster/health" -TimeoutSec 5
    $Kibana = Invoke-RestMethod "$KibanaUrl/api/status" -TimeoutSec 5
    $SocReady = (
        $Cluster.status -in @('green', 'yellow') -and
        $Kibana.status.overall.level -eq 'available'
    )
} catch {
    $SocReady = $false
}
if (-not $SocReady) {
    & (Join-Path $PSScriptRoot 'run-soc.ps1')
}

Write-Host '[2/5] Installing the alert index template'
$Template = Get-Content -Raw -Encoding UTF8 'deploy/elasticsearch/arsl-alerts-template.json'
Invoke-RestMethod -Method Put -Uri "$ElasticsearchUrl/_index_template/arsl-alerts" -ContentType 'application/json' -Body $Template -TimeoutSec 30 | Out-Null

Write-Host '[3/5] Executing the ES|QL detection pack'
$Python = Get-Command 'python' -ErrorAction SilentlyContinue
if (-not $Python) {
    throw 'Python 3.10 or later is required for the detection runner.'
}
$env:ARSL_ELASTICSEARCH_URL = $ElasticsearchUrl
& $Python.Source detection/esql_runner.py
if ($LASTEXITCODE -ne 0) {
    throw 'The ES|QL detection pack failed.'
}

Write-Host '[4/5] Importing the threat-mapping dashboard'
$Curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
if (-not $Curl) {
    throw 'curl.exe is required to import the Kibana dashboard.'
}
$DashboardPath = (Resolve-Path 'deploy/kibana/arsl-threat-dashboard.ndjson').Path
$CurlArguments = @(
    '--silent',
    '--show-error',
    '--request', 'POST',
    "$KibanaUrl/api/saved_objects/_import?overwrite=true",
    '--header', 'kbn-xsrf: arsl-phase6',
    '--form', "file=@$DashboardPath;type=application/ndjson"
)
$ImportOutput = & $Curl.Source @CurlArguments
if ($LASTEXITCODE -ne 0) {
    throw 'Kibana saved object import request failed.'
}
$ImportResult = $ImportOutput | ConvertFrom-Json
if (-not $ImportResult.success) {
    throw "Kibana threat dashboard import failed: $ImportOutput"
}

Write-Host '[5/5] Verifying detections and framework mappings'
& (Join-Path $PSScriptRoot 'verify-detections.ps1')

Write-Host "Threat dashboard: $KibanaUrl/app/dashboards#/view/arsl-threat-mapping"
