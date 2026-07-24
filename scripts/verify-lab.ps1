[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

Write-Host 'Running OPA policy tests'
docker compose exec -T opa opa test /policies -v
if ($LASTEXITCODE -ne 0) {
    throw 'OPA policy tests failed.'
}

$Expectations = [ordered]@{
    safe_document              = 'allow'
    indirect_prompt_injection  = 'deny'
    tool_misuse                = 'deny'
    data_exfiltration          = 'review'
}

$ReviewApprovalId = $null
$Results = foreach ($Entry in $Expectations.GetEnumerator()) {
    $Result = Invoke-RestMethod `
        -Method Post `
        -Uri "http://127.0.0.1:8080/api/scenarios/$($Entry.Key)" `
        -ContentType 'application/json' `
        -TimeoutSec 30

    if ($Result.decision.action -ne $Entry.Value) {
        throw "Scenario $($Entry.Key) expected $($Entry.Value), got $($Result.decision.action)."
    }
    if (-not $Result.expectation_met) {
        throw "Scenario expectation was not met: $($Entry.Key)"
    }
    if ($Entry.Value -eq 'allow' -and -not $Result.executed) {
        throw "Allowed scenario was not executed: $($Entry.Key)"
    }
    if ($Entry.Value -ne 'allow' -and $Result.executed) {
        throw "Blocked scenario unexpectedly executed: $($Entry.Key)"
    }
    if ($Entry.Value -eq 'review') {
        $ReviewApprovalId = $Result.approval.approval_id
        if (-not $ReviewApprovalId) {
            throw 'Review scenario did not create an approval request.'
        }
    }

    [PSCustomObject]@{
        Scenario = $Entry.Key
        Expected = $Entry.Value
        Actual   = $Result.decision.action
        Risk     = $Result.decision.risk_score
        Executed = $Result.executed
    }
}

$Results | Format-Table -AutoSize

Write-Host 'Running human approval capability test'
$ApprovalBody = @{
    approver = 'integration-reviewer'
    justification = 'Approved by the automated isolated-lab verification.'
} | ConvertTo-Json
$ApprovalResult = Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8080/api/approvals/$ReviewApprovalId/approve" `
    -ContentType 'application/json' `
    -Body $ApprovalBody `
    -TimeoutSec 30
if ($ApprovalResult.approval.status -ne 'approved' -or -not $ApprovalResult.execution.executed) {
    throw 'Approved invocation did not execute through the signed capability.'
}

$ReplayStatus = 0
try {
    Invoke-WebRequest `
        -Method Post `
        -Uri "http://127.0.0.1:8080/api/approvals/$ReviewApprovalId/approve" `
        -ContentType 'application/json' `
        -Body $ApprovalBody `
        -UseBasicParsing `
        -TimeoutSec 10 | Out-Null
    $ReplayStatus = 200
} catch {
    $ReplayStatus = [int]$_.Exception.Response.StatusCode
}
if ($ReplayStatus -ne 409) {
    throw "Approval replay expected HTTP 409, got $ReplayStatus."
}

$SecondReview = Invoke-RestMethod `
    -Method Post `
    -Uri 'http://127.0.0.1:8080/api/scenarios/data_exfiltration' `
    -ContentType 'application/json' `
    -TimeoutSec 30
$DenyBody = @{
    approver = 'integration-reviewer'
    justification = 'Denied by the automated isolated-lab verification.'
} | ConvertTo-Json
$DenyResult = Invoke-RestMethod `
    -Method Post `
    -Uri "http://127.0.0.1:8080/api/approvals/$($SecondReview.approval.approval_id)/deny" `
    -ContentType 'application/json' `
    -Body $DenyBody `
    -TimeoutSec 30
if ($DenyResult.approval.status -ne 'denied' -or $DenyResult.execution.executed) {
    throw 'Denied invocation was not retained as non-executed evidence.'
}

Write-Host 'Running Python security unit tests'
docker compose exec -T agent-api python -m unittest discover -s /app/tests -v
if ($LASTEXITCODE -ne 0) {
    throw 'Agent gateway unit tests failed.'
}
docker compose exec -T mcp-server python -m unittest discover -s /app/tests -v
if ($LASTEXITCODE -ne 0) {
    throw 'MCP server unit tests failed.'
}
docker compose exec -T auth-server python -m unittest discover -s /app/tests -v
if ($LASTEXITCODE -ne 0) {
    throw 'OAuth authorization server unit tests failed.'
}

Write-Host 'Running OAuth 2.1 MCP scope validation'
& (Join-Path $PSScriptRoot 'verify-oauth.ps1')

Write-Host 'Running intent-to-runtime correlation scenarios'
$RuntimeExpectations = [ordered]@{
    matched_file_read           = $true
    denied_process_bypass       = $false
    network_exfiltration_bypass = $false
}
$RuntimeResults = foreach ($Entry in $RuntimeExpectations.GetEnumerator()) {
    $Result = Invoke-RestMethod `
        -Method Post `
        -Uri "http://127.0.0.1:8080/api/runtime/scenarios/$($Entry.Key)" `
        -ContentType 'application/json' `
        -TimeoutSec 30
    if ($Result.finding.matched -ne $Entry.Value) {
        throw "Runtime scenario $($Entry.Key) returned an unexpected match result."
    }
    if (-not $Entry.Value -and $Result.finding.severity -notin @('High', 'Critical')) {
        throw "Runtime mismatch $($Entry.Key) did not produce a high-severity finding."
    }
    [PSCustomObject]@{
        Scenario = $Entry.Key
        Matched  = $Result.finding.matched
        Severity = $Result.finding.severity
        Type     = $Result.finding.finding_type
    }
}
$RuntimeResults | Format-Table -AutoSize

Write-Host 'Running signed sensor ingestion test'
$LatestIntent = @(Invoke-RestMethod 'http://127.0.0.1:8080/api/runtime/intents' -TimeoutSec 10)[0]
$SensorPayload = [ordered]@{
    container  = 'arsl-mcp-server'
    event_type = 'file_access'
    intent_id  = $LatestIntent.intent_id
    process    = 'python'
    source     = 'integration-sensor'
    target     = '/app/documents/public/guide.txt'
}
$SensorJson = $SensorPayload | ConvertTo-Json -Compress
$SensorBytes = [Text.Encoding]::UTF8.GetBytes($SensorJson)
$InvalidSensorStatus = 0
try {
    Invoke-WebRequest `
        -Method Post `
        -Uri 'http://127.0.0.1:8080/api/runtime/observations' `
        -Headers @{ 'X-Sensor-Signature' = ('0' * 64) } `
        -ContentType 'application/json' `
        -Body $SensorJson `
        -UseBasicParsing `
        -TimeoutSec 10 | Out-Null
    $InvalidSensorStatus = 200
} catch {
    $InvalidSensorStatus = [int]$_.Exception.Response.StatusCode
}
if ($InvalidSensorStatus -ne 401) {
    throw "Invalid sensor signature expected HTTP 401, got $InvalidSensorStatus."
}
$RuntimeSensorKey = $env:RUNTIME_SENSOR_HMAC_KEY
if (-not $RuntimeSensorKey) {
    $RuntimeSensorKey = (docker compose exec -T agent-api printenv RUNTIME_SENSOR_HMAC_KEY).Trim()
}
if ($RuntimeSensorKey.Length -lt 32) {
    throw 'Runtime sensor HMAC key is unavailable.'
}
$SensorKey = [Text.Encoding]::UTF8.GetBytes($RuntimeSensorKey)
$Hmac = [Security.Cryptography.HMACSHA256]::new($SensorKey)
try {
    $SensorSignature = ([BitConverter]::ToString($Hmac.ComputeHash($SensorBytes))).Replace('-', '').ToLowerInvariant()
} finally {
    $Hmac.Dispose()
}
$SensorResult = Invoke-RestMethod `
    -Method Post `
    -Uri 'http://127.0.0.1:8080/api/runtime/observations' `
    -Headers @{ 'X-Sensor-Signature' = $SensorSignature } `
    -ContentType 'application/json' `
    -Body $SensorJson `
    -TimeoutSec 10
if (-not $SensorResult.accepted) {
    throw 'The gateway rejected a correctly signed sensor observation.'
}

$RuntimeFindings = Invoke-RestMethod 'http://127.0.0.1:8080/api/runtime/findings' -TimeoutSec 10
if (@($RuntimeFindings).Count -lt ($RuntimeExpectations.Count + 1)) {
    throw 'The runtime monitor did not retain all correlation findings.'
}
$RuntimeOcsf = Invoke-RestMethod 'http://127.0.0.1:8080/api/runtime/ocsf' -TimeoutSec 10
if (@($RuntimeOcsf).Count -ne @($RuntimeFindings).Count) {
    throw 'Runtime OCSF export count does not match findings.'
}
if (@($RuntimeOcsf)[0].class_uid -ne 2004) {
    throw 'Runtime findings were not exported as OCSF Detection Finding.'
}
$RuntimeOcsfJson = $RuntimeOcsf | ConvertTo-Json -Depth 20
if ($RuntimeOcsfJson -match '/bin/sh' -or $RuntimeOcsfJson -match '203\.0\.113\.10') {
    throw 'Runtime OCSF export leaked raw observed targets.'
}

$Events = Invoke-RestMethod 'http://127.0.0.1:8080/api/events' -TimeoutSec 10
if (@($Events).Count -lt ($Expectations.Count + 3)) {
    throw 'The gateway did not retain all verification events.'
}

$OcsfEvents = Invoke-RestMethod 'http://127.0.0.1:8080/api/events/ocsf' -TimeoutSec 10
if (@($OcsfEvents).Count -lt ($Expectations.Count + 3)) {
    throw 'The gateway did not export all events as OCSF.'
}
$FirstOcsf = @($OcsfEvents)[0]
if ($FirstOcsf.class_uid -ne 6003 -or $FirstOcsf.metadata.version -ne '1.8.0') {
    throw 'OCSF API Activity metadata is invalid.'
}
$OcsfJson = $OcsfEvents | ConvertTo-Json -Depth 20
if ($OcsfJson -match 'evil\.example' -or $OcsfJson -match '\.\./\.\./etc/shadow') {
    throw 'OCSF export leaked raw tool arguments.'
}

$Jaeger = Invoke-WebRequest 'http://127.0.0.1:16686' -UseBasicParsing -TimeoutSec 10
if ($Jaeger.StatusCode -ne 200) {
    throw 'Jaeger UI is not available.'
}

Write-Host "Verification passed: $($Expectations.Count) policy scenarios, $($RuntimeExpectations.Count) runtime scenarios, signed sensor ingestion, approve/deny workflow, replay defense, and OCSF exports."
