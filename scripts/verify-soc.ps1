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

Write-Host 'Checking Elastic Stack health'
$Cluster = Invoke-RestMethod "$ElasticsearchUrl/_cluster/health" -TimeoutSec 10
if ($Cluster.status -notin @('green', 'yellow')) {
    throw "Elasticsearch cluster health is $($Cluster.status)."
}
$Logstash = Invoke-RestMethod "$LogstashUrl/_node/stats/pipelines" -TimeoutSec 10
if (-not $Logstash.pipelines.main) {
    throw 'The Logstash main pipeline is not running.'
}
$Dashboard = Invoke-RestMethod -Uri "$KibanaUrl/api/saved_objects/dashboard/arsl-soc-overview" -Headers @{ 'kbn-xsrf' = 'arsl-phase5' } -TimeoutSec 10
if ($Dashboard.attributes.title -notlike 'Agent Runtime Security*SOC Overview') {
    throw 'The expected Kibana SOC dashboard is not installed.'
}

Write-Host 'Checking OCSF ingestion and idempotency'
$AggregationBody = @{
    size = 0
    aggs = @{
        unique_documents = @{
            cardinality = @{
                field = 'metadata.uid'
                precision_threshold = 1000
            }
        }
        api_activity = @{
            filter = @{
                term = @{ class_uid = 6003 }
            }
        }
        detection_findings = @{
            filter = @{
                term = @{ class_uid = 2004 }
            }
        }
        critical_alerts = @{
            filter = @{
                bool = @{
                    filter = @(
                        @{ term = @{ class_uid = 2004 } },
                        @{ term = @{ severity = 'Critical' } },
                        @{ term = @{ is_alert = $true } }
                    )
                }
            }
        }
    }
} | ConvertTo-Json -Depth 12
$Search = Invoke-RestMethod -Method Post -Uri "$ElasticsearchUrl/arsl-ocsf-*/_search" -ContentType 'application/json' -Body $AggregationBody -TimeoutSec 30

$Total = [int]$Search.hits.total.value
$Unique = [int]$Search.aggregations.unique_documents.value
$ApiCount = [int]$Search.aggregations.api_activity.doc_count
$FindingCount = [int]$Search.aggregations.detection_findings.doc_count
$CriticalCount = [int]$Search.aggregations.critical_alerts.doc_count
if ($Total -lt 2 -or $ApiCount -lt 1 -or $FindingCount -lt 1) {
    throw 'The SOC index does not contain both OCSF API Activity and Detection Finding documents.'
}
if ($Total -ne $Unique) {
    throw 'Duplicate OCSF documents were indexed even though metadata.uid is the document ID.'
}
if ($CriticalCount -lt 1) {
    throw 'The SOC index does not contain the expected critical runtime mismatch.'
}

Write-Host 'Checking privacy boundary'
$Documents = Invoke-RestMethod -Method Post -Uri "$ElasticsearchUrl/arsl-ocsf-*/_search?size=500" -ContentType 'application/json' -Body '{"query":{"match_all":{}}}' -TimeoutSec 30
$Serialized = $Documents.hits.hits._source | ConvertTo-Json -Depth 30 -Compress
if ($Serialized -match 'evil\.example' -or
    $Serialized -match '\.\./\.\./etc/shadow' -or
    $Serialized -match '/bin/sh' -or
    $Serialized -match '203\.0\.113\.10') {
    throw 'Raw sensitive arguments or runtime targets crossed the OCSF privacy boundary.'
}

$Template = Invoke-RestMethod "$ElasticsearchUrl/_index_template/arsl-ocsf" -TimeoutSec 10
$Lifecycle = Invoke-RestMethod "$ElasticsearchUrl/_ilm/policy/arsl-ocsf-7d" -TimeoutSec 10
if (-not $Template.index_templates -or -not $Lifecycle.'arsl-ocsf-7d') {
    throw 'The OCSF index template or retention policy is missing.'
}

[PSCustomObject]@{
    Elasticsearch = $Cluster.status
    OCSFDocuments = $Total
    UniqueUIDs = $Unique
    APIActivities = $ApiCount
    DetectionFindings = $FindingCount
    CriticalAlerts = $CriticalCount
    Retention = '7 days'
    Dashboard = $Dashboard.attributes.title
} | Format-List

Write-Host 'Phase 5 SOC pipeline verification passed.'
