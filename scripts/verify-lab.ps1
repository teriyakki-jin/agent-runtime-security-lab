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

    [PSCustomObject]@{
        Scenario = $Entry.Key
        Expected = $Entry.Value
        Actual   = $Result.decision.action
        Risk     = $Result.decision.risk_score
        Executed = $Result.executed
    }
}

$Results | Format-Table -AutoSize

$Events = Invoke-RestMethod 'http://127.0.0.1:8080/api/events' -TimeoutSec 10
if (@($Events).Count -lt $Expectations.Count) {
    throw 'The gateway did not retain all verification events.'
}

$Jaeger = Invoke-WebRequest 'http://127.0.0.1:16686' -UseBasicParsing -TimeoutSec 10
if ($Jaeger.StatusCode -ne 200) {
    throw 'Jaeger UI is not available.'
}

Write-Host "Verification passed: $($Expectations.Count) scenarios, $(@($Events).Count) recorded events."
