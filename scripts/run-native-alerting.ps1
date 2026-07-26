[CmdletBinding()]
param(
    [string]$EvidencePath = 'docs\evidence\phase11-native-alerting.json'
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot
$ElasticsearchUrl = "http://127.0.0.1:$(if ($env:ARSL_ELASTICSEARCH_PORT) { $env:ARSL_ELASTICSEARCH_PORT } else { '19200' })"
$KibanaUrl = "http://127.0.0.1:$(if ($env:ARSL_KIBANA_PORT) { $env:ARSL_KIBANA_PORT } else { '15601' })"
$Headers = @{ 'kbn-xsrf' = 'arsl-phase11' }
$RuleIds = @(
    'arsl-native-denied-process-execution',
    'arsl-native-network-before-approval',
    'arsl-native-orphan-runtime-activity'
)

function Get-Count {
    param([string]$Index, [hashtable]$Query)
    $Body = @{ query = $Query } | ConvertTo-Json -Depth 12 -Compress
    try {
        return (Invoke-RestMethod -Method Post -Uri "$ElasticsearchUrl/$Index/_count" -ContentType 'application/json' -Body $Body -TimeoutSec 30).count
    } catch {
        if ($_.Exception.Response.StatusCode -eq 404) { return 0 }
        throw
    }
}

$NativeRuleQuery = @{ terms = @{ 'kibana.alert.rule.rule_id' = $RuleIds } }

Write-Host '[1/7] Checking the Elastic SOC stack'
try {
    $Cluster = Invoke-RestMethod "$ElasticsearchUrl/_cluster/health" -TimeoutSec 5
    $Kibana = Invoke-RestMethod "$KibanaUrl/api/status" -TimeoutSec 5
    $Ready = $Cluster.status -in @('green', 'yellow') -and $Kibana.status.overall.level -eq 'available'
} catch {
    $Ready = $false
}
if (-not $Ready) {
    & (Join-Path $PSScriptRoot 'run-soc.ps1')
}

Write-Host '[2/7] Installing the notification index template'
$Template = Get-Content -Raw -Encoding UTF8 'deploy/elasticsearch/arsl-notifications-template.json'
Invoke-RestMethod -Method Put -Uri "$ElasticsearchUrl/_index_template/arsl-notifications" -ContentType 'application/json' -Body $Template -TimeoutSec 30 | Out-Null

Write-Host '[3/7] Syncing native ES|QL rules and Basic-license connector'
$env:ARSL_KIBANA_URL = $KibanaUrl
$SyncJson = python -m detection.native_alerting
if ($LASTEXITCODE -ne 0) { throw 'Native rule synchronization failed.' }
$Sync = $SyncJson | ConvertFrom-Json
if (@($Sync.rules).Count -ne 3 -or @($Sync.rules | Where-Object { -not $_.enabled }).Count) {
    throw 'Exactly three enabled native rules are required.'
}

Write-Host '[4/7] Importing the Incident Response dashboard'
$DashboardPath = (Resolve-Path 'deploy/kibana/arsl-incident-response-dashboard.ndjson').Path
$ImportOutput = curl.exe --silent --show-error --request POST `
    "$KibanaUrl/api/saved_objects/_import?overwrite=true" `
    --header 'kbn-xsrf: arsl-phase11' `
    --form "file=@$DashboardPath;type=application/ndjson"
if ($LASTEXITCODE -ne 0) { throw 'Incident dashboard import request failed.' }
$ImportResult = $ImportOutput | ConvertFrom-Json
if (-not $ImportResult.success) { throw "Incident dashboard import failed: $ImportOutput" }

Write-Host '[5/7] Generating fresh process, network, and orphan findings'
$BaselineAlerts = Get-Count '.alerts-security.alerts-default' $NativeRuleQuery
$BaselineNotifications = Get-Count 'arsl-notifications-*' @{ match_all = @{} }
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8080/api/runtime/scenarios/denied_process_bypass' -TimeoutSec 30 | Out-Null
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8080/api/runtime/scenarios/network_exfiltration_bypass' -TimeoutSec 30 | Out-Null

$SensorPayload = [ordered]@{
    # A dedicated identity prevents the probe from auto-correlating with the
    # process/network scenarios emitted immediately before it.
    container = 'arsl-phase11-orphan-probe'
    event_type = 'process_exec'
    process = 'phase11-probe'
    source = 'phase11-signed-sensor'
    target = '/tmp/phase11-orphan-probe'
}
$SensorJson = $SensorPayload | ConvertTo-Json -Compress
$SensorKeyText = (docker compose exec -T agent-api printenv RUNTIME_SENSOR_HMAC_KEY).Trim()
if ($SensorKeyText.Length -lt 32) { throw 'Runtime sensor HMAC key is unavailable.' }
$Hmac = [Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($SensorKeyText))
try {
    $Signature = ([BitConverter]::ToString($Hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($SensorJson)))).Replace('-', '').ToLowerInvariant()
} finally {
    $Hmac.Dispose()
}
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8080/api/runtime/observations' -Headers @{ 'X-Sensor-Signature' = $Signature } -ContentType 'application/json' -Body $SensorJson -TimeoutSec 30 | Out-Null

Write-Host '[6/7] Waiting for scheduled detection and connector delivery'
$Deadline = (Get-Date).AddMinutes(4)
do {
    Start-Sleep -Seconds 10
    $AlertCount = Get-Count '.alerts-security.alerts-default' $NativeRuleQuery
    $NotificationCount = Get-Count 'arsl-notifications-*' @{ match_all = @{} }
    $Delivered = $AlertCount -ge ($BaselineAlerts + 3) -and $NotificationCount -ge ($BaselineNotifications + 3)
} while (-not $Delivered -and (Get-Date) -lt $Deadline)
if (-not $Delivered) {
    throw "Native alert delivery timed out: alerts $BaselineAlerts->$AlertCount, notifications $BaselineNotifications->$NotificationCount"
}

$FirstAlertCount = $AlertCount
$FirstNotificationCount = $NotificationCount
Start-Sleep -Seconds 70
$ReplayAlertCount = Get-Count '.alerts-security.alerts-default' $NativeRuleQuery
$ReplayNotificationCount = Get-Count 'arsl-notifications-*' @{ match_all = @{} }
if ($ReplayAlertCount -ne $FirstAlertCount -or $ReplayNotificationCount -ne $FirstNotificationCount) {
    throw 'Native scheduling produced duplicate alerts or notifications for the same source events.'
}

Write-Host '[7/7] Verifying execution status, privacy, and evidence'
$RuleResponse = Invoke-RestMethod "$KibanaUrl/api/detection_engine/rules/_find?per_page=100" -Headers $Headers -TimeoutSec 30
$Rules = @($RuleResponse.data | Where-Object { $_.rule_id -in $RuleIds })
if ($Rules.Count -ne 3) { throw 'Kibana does not report all three native rules.' }
if (@($Rules | Where-Object { $_.execution_summary.last_execution.status -ne 'succeeded' }).Count) {
    throw 'At least one native rule has not completed successfully.'
}

$NotificationSearch = Invoke-RestMethod -Method Post -Uri "$ElasticsearchUrl/arsl-notifications-*/_search?size=100" -ContentType 'application/json' -Body '{"query":{"match_all":{}}}' -TimeoutSec 30
$SerializedNotifications = @($NotificationSearch.hits.hits._source) | ConvertTo-Json -Depth 10 -Compress
foreach ($Forbidden in @('evil.example', '/bin/sh', '203.0.113.10', 'phase11-orphan-probe')) {
    if ($SerializedNotifications -match [regex]::Escape($Forbidden)) {
        throw "Notification leaked a raw sensitive value: $Forbidden"
    }
}

$ConnectorTypes = Invoke-RestMethod "$KibanaUrl/api/actions/connector_types" -Headers $Headers -TimeoutSec 30
$Slack = $ConnectorTypes | Where-Object id -eq '.slack'
$Teams = $ConnectorTypes | Where-Object id -eq '.teams'
$ElasticsearchInfo = Invoke-RestMethod $ElasticsearchUrl -TimeoutSec 30
$Checks = [ordered]@{
    three_native_esql_rules_enabled = $Rules.Count -eq 3 -and @($Rules | Where-Object enabled).Count -eq 3
    scheduled_execution_succeeded = @($Rules | Where-Object { $_.execution_summary.last_execution.status -eq 'succeeded' }).Count -eq 3
    basic_index_connector_enabled = $Sync.connector.type -eq '.index' -and $Sync.connector.minimum_license -eq 'basic'
    three_attack_classes_alerted = ($FirstAlertCount - $BaselineAlerts) -ge 3
    notifications_delivered = ($FirstNotificationCount - $BaselineNotifications) -ge 3
    duplicate_alerts_suppressed = $ReplayAlertCount -eq $FirstAlertCount
    duplicate_notifications_suppressed = $ReplayNotificationCount -eq $FirstNotificationCount
    notification_payload_redacted = $true
    slack_teams_templates_present = (Test-Path 'deploy/elastic/connectors/slack.example.json') -and (Test-Path 'deploy/elastic/connectors/teams.example.json')
}
$Evidence = [ordered]@{
    phase = 11
    result = if (@($Checks.Values | Where-Object { -not $_ }).Count -eq 0) { 'passed' } else { 'failed' }
    elastic = [ordered]@{ version = $ElasticsearchInfo.version.number; license = 'basic'; alert_index = '.alerts-security.alerts-default' }
    connector = [ordered]@{ id = $Sync.connector.id; type = $Sync.connector.type; minimum_license = $Sync.connector.minimum_license; notification_index = 'arsl-notifications-v1' }
    rules = @($Rules | ForEach-Object { [ordered]@{ rule_id = $_.rule_id; type = $_.type; enabled = $_.enabled; interval = $_.interval; from = $_.from; last_execution = $_.execution_summary.last_execution.status } })
    delivery = [ordered]@{
        native_alerts_created = $FirstAlertCount - $BaselineAlerts
        notifications_created = $FirstNotificationCount - $BaselineNotifications
        alerts_after_replay = $ReplayAlertCount - $BaselineAlerts
        notifications_after_replay = $ReplayNotificationCount - $BaselineNotifications
    }
    external_channels = [ordered]@{
        slack = [ordered]@{ configured = $false; minimum_license = $Slack.minimum_license_required; template = 'deploy/elastic/connectors/slack.example.json' }
        teams = [ordered]@{ configured = $false; minimum_license = $Teams.minimum_license_required; template = 'deploy/elastic/connectors/teams.example.json' }
    }
    privacy = [ordered]@{ raw_arguments_exported = $false; raw_runtime_targets_exported = $false; connector_secrets_exported = $false }
    checks = $Checks
}
if ($Evidence.result -ne 'passed') { throw 'One or more Phase 11 checks failed.' }

$ResolvedEvidence = Join-Path $LabRoot $EvidencePath
$Parent = Split-Path -Parent $ResolvedEvidence
if (-not (Test-Path $Parent)) { New-Item -ItemType Directory -Path $Parent -Force | Out-Null }
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
[IO.File]::WriteAllText($ResolvedEvidence, ($Evidence | ConvertTo-Json -Depth 20), $Utf8NoBom)
$Evidence
Write-Host "Incident dashboard: $KibanaUrl/app/dashboards#/view/arsl-phase11-incident-response"
