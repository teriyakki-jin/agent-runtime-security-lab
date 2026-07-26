[CmdletBinding()]
param(
    [switch]$StopSensor
)

$ErrorActionPreference = 'Stop'
$LabRoot = Split-Path -Parent $PSScriptRoot
Set-Location $LabRoot

$TetragonContainer = 'arsl-tetragon'
$TetragonImage = 'quay.io/cilium/tetragon:v1.7.0'
$TetragonDigest = 'quay.io/cilium/tetragon@sha256:deda51c3f88e4d26b4d76c99ea207f2b05f9e40c210e0f04a37ca632ab7bf527'
$PolicyName = 'arsl-runtime-observation'
$PolicyPath = Join-Path $LabRoot 'deploy\tetragon\runtime-observation.yaml'
$DockerExe = (Get-Command docker -ErrorAction Stop).Source
$PythonExe = (Get-Command python -ErrorAction Stop).Source
$TempFiles = [Collections.Generic.List[string]]::new()
$PreviousSensorKey = $env:RUNTIME_SENSOR_HMAC_KEY

function Wait-AgentGateway {
    $Deadline = (Get-Date).AddSeconds(60)
    do {
        Start-Sleep -Seconds 2
        try {
            $Health = Invoke-RestMethod 'http://127.0.0.1:8080/health' -TimeoutSec 3
            if ($Health.status -eq 'ok') {
                return
            }
        } catch {
            # Continue until the bounded deadline.
        }
    } while ((Get-Date) -lt $Deadline)
    throw 'Agent gateway did not become healthy.'
}

function Start-TetragonCapture {
    param(
        [Parameter(Mandatory)]
        [ValidateSet('PROCESS_EXEC', 'PROCESS_KPROBE')]
        [string]$EventType
    )

    $CaptureId = [Guid]::NewGuid().ToString('N')
    $OutputPath = Join-Path ([IO.Path]::GetTempPath()) "arsl-tetragon-$CaptureId.jsonl"
    $ErrorPath = Join-Path ([IO.Path]::GetTempPath()) "arsl-tetragon-$CaptureId.err"
    $TempFiles.Add($OutputPath)
    $TempFiles.Add($ErrorPath)

    $Arguments = @(
        'exec', $TetragonContainer,
        'timeout', '10',
        'tetra', 'getevents',
        '-e', $EventType,
        '-o', 'json'
    )
    if ($EventType -eq 'PROCESS_KPROBE') {
        $Arguments += @('--policy-names', $PolicyName)
    } else {
        $Arguments += @('--process', 'python')
    }

    $Process = Start-Process `
        -FilePath $DockerExe `
        -ArgumentList $Arguments `
        -RedirectStandardOutput $OutputPath `
        -RedirectStandardError $ErrorPath `
        -WindowStyle Hidden `
        -PassThru

    [PSCustomObject]@{
        Process = $Process
        OutputPath = $OutputPath
        ErrorPath = $ErrorPath
    }
}

function Complete-TetragonCapture {
    param(
        [Parameter(Mandatory)]
        $Capture
    )
    if (-not $Capture.Process.WaitForExit(20000)) {
        throw 'Timed out waiting for the bounded Tetragon capture.'
    }
    if (-not (Test-Path -LiteralPath $Capture.OutputPath)) {
        throw 'Tetragon capture output was not created.'
    }
    if ((Get-Item -LiteralPath $Capture.OutputPath).Length -eq 0) {
        $CaptureError = Get-Content -LiteralPath $Capture.ErrorPath -Raw
        throw "Tetragon produced no matching events. $CaptureError"
    }
}

function Submit-TetragonCapture {
    param(
        [Parameter(Mandatory)]
        [string]$Path,
        [Parameter(Mandatory)]
        [ValidateSet('file_access', 'process_exec')]
        [string]$EventType,
        [Parameter(Mandatory)]
        [string]$ContainerAlias
    )

    & $PythonExe -m sensor.tetragon_adapter `
        --input $Path `
        --gateway http://127.0.0.1:8080 `
        --container-alias $ContainerAlias `
        --container-name arsl-mcp-server `
        --include-event-type $EventType `
        --max-events 1
    if ($LASTEXITCODE -ne 0) {
        throw "Tetragon adapter failed for $EventType."
    }
}

try {
    Write-Host '[1/6] Checking the hardened application lab'
    $PreviousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    docker info *> $null
    $DockerInfoExitCode = $LASTEXITCODE
    $ErrorActionPreference = $PreviousErrorAction
    if ($DockerInfoExitCode -ne 0) {
        throw 'Docker Desktop is not running.'
    }
    Wait-AgentGateway

    Write-Host '[2/6] Starting the privileged Tetragon eBPF sensor'
    $SensorExists = docker ps -a --filter "name=^/$TetragonContainer$" --format '{{.Names}}'
    if (-not $SensorExists) {
        docker run -d `
            --name $TetragonContainer `
            --pid=host `
            --cgroupns=host `
            --privileged `
            -v /sys/kernel/btf/vmlinux:/var/lib/tetragon/btf:ro `
            $TetragonImage | Out-Null
        if ($LASTEXITCODE -ne 0) {
            throw 'Tetragon container failed to start.'
        }
    } else {
        $ExistingSensorImage = docker inspect --format '{{.Config.Image}}' $TetragonContainer
        if ($ExistingSensorImage -ne $TetragonImage) {
            throw "Existing $TetragonContainer uses unexpected image $ExistingSensorImage."
        }
        $SensorRunning = docker inspect --format '{{.State.Running}}' $TetragonContainer
        if ($SensorRunning -ne 'true') {
            docker start $TetragonContainer | Out-Null
        }
    }
    $SensorPrivilege = docker inspect --format '{{.HostConfig.Privileged}}' $TetragonContainer
    $SensorPidMode = docker inspect --format '{{.HostConfig.PidMode}}' $TetragonContainer
    $SensorCgroupMode = docker inspect --format '{{.HostConfig.CgroupnsMode}}' $TetragonContainer
    if ($SensorPrivilege -ne 'true' -or
        $SensorPidMode -ne 'host' -or
        $SensorCgroupMode -ne 'host') {
        throw 'Tetragon container does not have the explicitly required sensor isolation settings.'
    }
    $SensorDigests = docker image inspect $TetragonImage --format '{{json .RepoDigests}}'
    if ($LASTEXITCODE -ne 0 -or
        [string]::IsNullOrWhiteSpace($SensorDigests) -or
        $SensorDigests -notmatch [Regex]::Escape($TetragonDigest)) {
        throw 'Tetragon image digest does not match the Phase 4 verified artifact.'
    }

    $SensorDeadline = (Get-Date).AddSeconds(90)
    do {
        Start-Sleep -Seconds 2
        $SensorLogs = docker logs --tail 120 $TetragonContainer 2>&1
        $SensorReady = $SensorLogs -match 'Listening for events'
    } while (-not $SensorReady -and (Get-Date) -lt $SensorDeadline)
    if (-not $SensorReady) {
        throw "Tetragon did not attach its eBPF sensors. $SensorLogs"
    }
    $PreviousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    docker exec $TetragonContainer sh -c 'test -r /sys/kernel/btf/vmlinux' *> $null
    $BtfExitCode = $LASTEXITCODE
    $ErrorActionPreference = $PreviousErrorAction
    if ($BtfExitCode -ne 0) {
        throw 'Tetragon did not confirm kernel BTF discovery.'
    }

    Write-Host '[3/6] Loading the monitor-only TracingPolicy'
    docker cp $PolicyPath "${TetragonContainer}:/tmp/runtime-observation.yaml" | Out-Null
    $Policies = (docker exec $TetragonContainer tetra tracingpolicy list) -join "`n"
    if ($Policies -notmatch [Regex]::Escape($PolicyName)) {
        docker exec $TetragonContainer tetra tracingpolicy add /tmp/runtime-observation.yaml
        if ($LASTEXITCODE -ne 0) {
            throw 'Tetragon TracingPolicy failed to load.'
        }
    }

    Write-Host '[4/6] Restarting app processes after sensor attachment'
    docker compose restart mcp-server agent-api | Out-Null
    Wait-AgentGateway
    $McpContainerId = docker inspect --format '{{.Id}}' arsl-mcp-server
    if ($McpContainerId.Length -lt 12) {
        throw 'Could not resolve the MCP container ID.'
    }
    $ContainerAlias = "$McpContainerId=arsl-mcp-server"
    $env:RUNTIME_SENSOR_HMAC_KEY = (
        docker exec arsl-agent-api printenv RUNTIME_SENSOR_HMAC_KEY
    ).Trim()
    if ($env:RUNTIME_SENSOR_HMAC_KEY.Length -lt 32) {
        throw 'Could not resolve the runtime sensor HMAC key.'
    }

    Write-Host '[5/6] Capturing a real file-access match'
    $FileCapture = Start-TetragonCapture -EventType PROCESS_KPROBE
    Start-Sleep -Seconds 2
    $SafeEvent = Invoke-RestMethod `
        -Method Post `
        -Uri 'http://127.0.0.1:8080/api/scenarios/safe_document' `
        -ContentType 'application/json' `
        -TimeoutSec 30
    if (-not $SafeEvent.executed) {
        throw 'Safe document scenario did not execute.'
    }
    Complete-TetragonCapture -Capture $FileCapture
    Submit-TetragonCapture `
        -Path $FileCapture.OutputPath `
        -EventType file_access `
        -ContainerAlias $ContainerAlias
    $AllFindings = Invoke-RestMethod 'http://127.0.0.1:8080/api/runtime/findings'
    $FileFinding = $AllFindings.Where({
        $_.observation.source -eq 'tetragon' -and
        $_.observation.event_type -eq 'file_access'
    }) | Select-Object -First 1
    if (-not $FileFinding.matched -or
        $FileFinding.observation.correlation_method -ne 'container_time_window') {
        throw 'Real file observation was not automatically matched to its intent.'
    }

    Write-Host '[6/6] Capturing a real process execution after policy deny'
    $ProcessCapture = Start-TetragonCapture -EventType PROCESS_EXEC
    Start-Sleep -Seconds 2
    $DeniedEvent = Invoke-RestMethod `
        -Method Post `
        -Uri 'http://127.0.0.1:8080/api/scenarios/tool_misuse' `
        -ContentType 'application/json' `
        -TimeoutSec 30
    if ($DeniedEvent.executed) {
        throw 'Tool misuse scenario unexpectedly executed.'
    }
    docker exec arsl-mcp-server python -c "print('phase4-denied-process-bypass')" | Out-Null
    Complete-TetragonCapture -Capture $ProcessCapture
    Submit-TetragonCapture `
        -Path $ProcessCapture.OutputPath `
        -EventType process_exec `
        -ContainerAlias $ContainerAlias
    $AllFindings = Invoke-RestMethod 'http://127.0.0.1:8080/api/runtime/findings'
    $ProcessFinding = $AllFindings.Where({
        $_.observation.source -eq 'tetragon' -and
        $_.observation.event_type -eq 'process_exec'
    }) | Select-Object -First 1
    if ($ProcessFinding.matched -or
        $ProcessFinding.severity -ne 'Critical' -or
        $ProcessFinding.observation.correlation_method -ne 'container_time_window') {
        throw 'Real process execution was not detected as an auto-correlated mismatch.'
    }

    $Status = Invoke-RestMethod 'http://127.0.0.1:8080/api/runtime/status'
    if ($Status.sensor_mode -ne 'tetragon' -or $Status.auto_correlated -lt 2) {
        throw 'Gateway runtime status does not show the live Tetragon sensor.'
    }

    [PSCustomObject]@{
        Sensor = 'Tetragon v1.7.0'
        BTF = 'detected'
        Policy = $PolicyName
        FileAccess = $FileFinding.finding_type
        ProcessBypass = $ProcessFinding.finding_type
        ProcessSeverity = $ProcessFinding.severity
        Correlation = $ProcessFinding.observation.correlation_method
    } | Format-List
    Write-Host 'Live Tetragon eBPF verification passed.'
} finally {
    if ($null -eq $PreviousSensorKey) {
        Remove-Item Env:RUNTIME_SENSOR_HMAC_KEY -ErrorAction SilentlyContinue
    } else {
        $env:RUNTIME_SENSOR_HMAC_KEY = $PreviousSensorKey
    }
    foreach ($TempFile in $TempFiles) {
        if (Test-Path -LiteralPath $TempFile) {
            Remove-Item -LiteralPath $TempFile -Force
        }
    }
    if ($StopSensor -and (docker ps -q --filter "name=^/$TetragonContainer$")) {
        docker stop $TetragonContainer | Out-Null
    }
}
