[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot
$ElasticsearchPort = if ($env:ARSL_ELASTICSEARCH_PORT) { $env:ARSL_ELASTICSEARCH_PORT } else { '19200' }
$KibanaPort = if ($env:ARSL_KIBANA_PORT) { $env:ARSL_KIBANA_PORT } else { '15601' }
$LogstashPort = if ($env:ARSL_LOGSTASH_PORT) { $env:ARSL_LOGSTASH_PORT } else { '19600' }
$ElasticsearchUrl = "http://127.0.0.1:$ElasticsearchPort"
$KibanaUrl = "http://127.0.0.1:$KibanaPort"
$LogstashUrl = "http://127.0.0.1:$LogstashPort"

function Wait-Endpoint {
    param(
        [Parameter(Mandatory)]
        [string]$Uri,
        [Parameter(Mandatory)]
        [string]$Name,
        [int]$TimeoutSeconds = 300
    )

    $Deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    do {
        Start-Sleep -Seconds 5
        try {
            $Response = Invoke-WebRequest -Uri $Uri -UseBasicParsing -TimeoutSec 5
            if ($Response.StatusCode -eq 200) {
                return
            }
        } catch {
            # The service is still starting.
        }
    } while ((Get-Date) -lt $Deadline)
    throw "$Name did not become ready within $TimeoutSeconds seconds."
}

Write-Host '[1/6] Checking the base security lab'
$PreviousErrorAction = $ErrorActionPreference
$ErrorActionPreference = 'Continue'
docker info *> $null
$DockerInfoExitCode = $LASTEXITCODE
$ErrorActionPreference = $PreviousErrorAction
if ($DockerInfoExitCode -ne 0) {
    throw 'Docker Desktop is not running.'
}

try {
    $Agent = Invoke-RestMethod 'http://127.0.0.1:8080/health' -TimeoutSec 5
    $BaseReady = $Agent.status -eq 'ok'
} catch {
    $BaseReady = $false
}
if (-not $BaseReady) {
    & (Join-Path $PSScriptRoot 'run-lab.ps1')
}

Write-Host '[2/6] Starting Elasticsearch and Kibana 9.4.2'
docker compose --profile soc up -d elasticsearch kibana
if ($LASTEXITCODE -ne 0) {
    throw 'Elastic Stack startup failed.'
}
Wait-Endpoint -Uri "$ElasticsearchUrl/_cluster/health" -Name 'Elasticsearch'
Wait-Endpoint -Uri "$KibanaUrl/api/status" -Name 'Kibana'

Write-Host '[3/6] Installing the OCSF lifecycle policy and index template'
$Lifecycle = @{
    policy = @{
        phases = @{
            hot = @{
                min_age = '0ms'
                actions = @{}
            }
            delete = @{
                min_age = '7d'
                actions = @{
                    delete = @{}
                }
            }
        }
    }
} | ConvertTo-Json -Depth 10
Invoke-RestMethod -Method Put -Uri "$ElasticsearchUrl/_ilm/policy/arsl-ocsf-7d" -ContentType 'application/json' -Body $Lifecycle -TimeoutSec 30 | Out-Null

$TemplatePath = Join-Path $LabRoot 'deploy/elasticsearch/arsl-ocsf-template.json'
$Template = Get-Content -Raw -Encoding UTF8 -LiteralPath $TemplatePath
Invoke-RestMethod -Method Put -Uri "$ElasticsearchUrl/_index_template/arsl-ocsf" -ContentType 'application/json' -Body $Template -TimeoutSec 30 | Out-Null

Write-Host '[4/6] Importing the SOC dashboard'
$Curl = Get-Command 'curl.exe' -ErrorAction SilentlyContinue
if (-not $Curl) {
    throw 'curl.exe is required to import the portable Kibana saved objects.'
}
$DashboardPath = (Resolve-Path 'deploy/kibana/arsl-soc-dashboard.ndjson').Path
$CurlArguments = @(
    '--silent',
    '--show-error',
    '--request', 'POST',
    "$KibanaUrl/api/saved_objects/_import?overwrite=true",
    '--header', 'kbn-xsrf: arsl-phase5',
    '--form', "file=@$DashboardPath;type=application/ndjson"
)
$ImportOutput = & $Curl.Source @CurlArguments
if ($LASTEXITCODE -ne 0) {
    throw 'Kibana saved object import request failed.'
}
$ImportResult = $ImportOutput | ConvertFrom-Json
if (-not $ImportResult.success) {
    throw "Kibana dashboard import failed: $ImportOutput"
}

Write-Host '[5/6] Starting the OCSF Logstash pipeline'
docker compose --profile soc up -d logstash
if ($LASTEXITCODE -ne 0) {
    throw 'Logstash startup failed.'
}
Wait-Endpoint -Uri "$LogstashUrl/_node/pipelines" -Name 'Logstash'

$DocumentDeadline = (Get-Date).AddMinutes(3)
do {
    Start-Sleep -Seconds 5
    try {
        $Count = Invoke-RestMethod "$ElasticsearchUrl/arsl-ocsf-*/_count" -TimeoutSec 5
        $DocumentsReady = $Count.count -gt 0
    } catch {
        $DocumentsReady = $false
    }
} while (-not $DocumentsReady -and (Get-Date) -lt $DocumentDeadline)
if (-not $DocumentsReady) {
    throw 'Logstash did not index OCSF documents within 3 minutes.'
}

Write-Host '[6/6] Verifying the SOC pipeline'
& (Join-Path $PSScriptRoot 'verify-soc.ps1')

Write-Host "Kibana SOC  : $KibanaUrl/app/dashboards#/view/arsl-soc-overview"
Write-Host "Elasticsearch: $ElasticsearchUrl"
Write-Host "Logstash API : $LogstashUrl"
