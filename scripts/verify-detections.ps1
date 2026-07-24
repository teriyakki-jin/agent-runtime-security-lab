[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot
$ElasticsearchPort = if ($env:ARSL_ELASTICSEARCH_PORT) { $env:ARSL_ELASTICSEARCH_PORT } else { '19200' }
$KibanaPort = if ($env:ARSL_KIBANA_PORT) { $env:ARSL_KIBANA_PORT } else { '15601' }
$ElasticsearchUrl = "http://127.0.0.1:$ElasticsearchPort"
$KibanaUrl = "http://127.0.0.1:$KibanaPort"

Write-Host 'Checking the detection pack and dashboard'
$Pack = Get-Content -Raw -Encoding UTF8 'deploy/elastic/detection-rules/agent-runtime-rules.json' | ConvertFrom-Json
if (@($Pack.rules).Count -ne 3) {
    throw 'The Phase 6 detection pack must contain exactly three rules.'
}
$Dashboard = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/dashboard/arsl-threat-mapping" -Headers @{ 'kbn-xsrf' = 'arsl-phase6' } -TimeoutSec 10
if ($Dashboard.attributes.title -notlike 'Agent Runtime Security*Threat Detection') {
    throw 'The Phase 6 Kibana dashboard is not installed.'
}

Write-Host 'Checking idempotent detection execution'
$Before = (Invoke-RestMethod "$ElasticsearchUrl/arsl-alerts-*/_count" -TimeoutSec 10).count
$Python = Get-Command 'python' -ErrorAction Stop
$env:ARSL_ELASTICSEARCH_URL = $ElasticsearchUrl
& $Python.Source detection/esql_runner.py | Out-Null
if ($LASTEXITCODE -ne 0) {
    throw 'The repeat detection execution failed.'
}
$After = (Invoke-RestMethod "$ElasticsearchUrl/arsl-alerts-*/_count" -TimeoutSec 10).count
if ($Before -ne $After) {
    throw "Detection alert count changed during repeat execution: $Before -> $After."
}

$Search = Invoke-RestMethod -Method Post -Uri "$ElasticsearchUrl/arsl-alerts-*/_search?size=500" -ContentType 'application/json' -Body '{"query":{"match_all":{}}}' -TimeoutSec 30
$Alerts = @($Search.hits.hits._source)
if ($Alerts.Count -lt 3) {
    throw 'The alert index does not contain enough detection evidence.'
}
$UniqueKeys = @(
    $Alerts |
        ForEach-Object { "$($_.rule.id):$($_.source.uid)" } |
        Sort-Object -Unique
).Count
if ($UniqueKeys -ne $Alerts.Count) {
    throw 'Duplicate rule and source UID pairs were indexed.'
}

$RuleIds = @($Alerts | ForEach-Object { $_.rule.id } | Sort-Object -Unique)
foreach ($ExpectedRule in @(
    'arsl-denied-process-execution',
    'arsl-network-before-approval',
    'arsl-orphan-runtime-activity'
)) {
    if ($ExpectedRule -notin $RuleIds) {
        throw "Expected detection rule did not produce evidence: $ExpectedRule."
    }
}

Write-Host 'Checking OWASP and MITRE mappings'
$OwaspIds = @(
    $Alerts |
        ForEach-Object { $_.threat.owasp_agentic } |
        ForEach-Object { $_.uid } |
        Sort-Object -Unique
)
$MitreIds = @(
    $Alerts |
        ForEach-Object { $_.threat.mitre_attack } |
        ForEach-Object { $_.technique.uid } |
        Sort-Object -Unique
)
foreach ($ExpectedOwasp in @('ASI02', 'ASI05', 'ASI10')) {
    if ($ExpectedOwasp -notin $OwaspIds) {
        throw "Missing OWASP Agentic mapping: $ExpectedOwasp."
    }
}
foreach ($ExpectedMitre in @('T1041', 'T1059')) {
    if ($ExpectedMitre -notin $MitreIds) {
        throw "Missing MITRE ATT&CK mapping: $ExpectedMitre."
    }
}

$Serialized = $Alerts | ConvertTo-Json -Depth 30 -Compress
if ($Serialized -match 'evil\.example' -or
    $Serialized -match '\.\./\.\./etc/shadow' -or
    $Serialized -match '/bin/sh' -or
    $Serialized -match '203\.0\.113\.10') {
    throw 'A detection alert contains raw sensitive arguments or runtime targets.'
}

$Template = Invoke-RestMethod "$ElasticsearchUrl/_index_template/arsl-alerts" -TimeoutSec 10
if (-not $Template.index_templates) {
    throw 'The alert index template is missing.'
}
$Critical = @($Alerts | Where-Object { $_.rule.severity -eq 'critical' }).Count
[PSCustomObject]@{
    DetectionRules = @($Pack.rules).Count
    Alerts = $Alerts.Count
    UniqueRuleSourcePairs = $UniqueKeys
    CriticalAlerts = $Critical
    OwaspMappings = $OwaspIds -join ', '
    MitreTechniques = $MitreIds -join ', '
    RepeatCount = "$Before -> $After"
    Dashboard = $Dashboard.attributes.title
} | Format-List

Write-Host 'Phase 6 threat detection verification passed.'
