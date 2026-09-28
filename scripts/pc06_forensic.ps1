# SPEMCS Forensic Evidence Collector for PC06
# Read-Only Forensic Extraction Script
$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SPEMCS LIVE PC06 UI LAUNCH FORENSIC COLLECTOR          " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

$evidence = [ordered]@{}
$evidence["TimestampUtc"] = [DateTime]::UtcNow.ToString("o")
$evidence["ComputerName"] = $env:COMPUTERNAME
$evidence["UserName"] = "$env:USERDOMAIN\$env:USERNAME"

# -------------------------------------------------------------
# PHASE 1 — VERIFY WHAT IS ACTUALLY INSTALLED
# -------------------------------------------------------------
Write-Host "`n[PHASE 1] Collecting Installed Binary Information..." -ForegroundColor Yellow
$installFolder = "C:\Program Files\SPEMCS\Endpoint Agent"
$serviceExePath = Join-Path $installFolder "Spemcs.Agent.Service.exe"
$uiExePath = Join-Path $installFolder "Spemcs.Agent.UI.exe"

$binaries = [ordered]@{}
foreach ($bPath in @($serviceExePath, $uiExePath)) {
    $bName = Split-Path -Leaf $bPath
    if (Test-Path $bPath) {
        $item = Get-Item $bPath
        $hash = (Get-FileHash -Path $bPath -Algorithm SHA256).Hash
        $vi = $item.VersionInfo
        $binaries[$bName] = [ordered]@{
            Exists = $true
            Path = $bPath
            FileVersion = $vi.FileVersion
            ProductVersion = $vi.ProductVersion
            LastWriteTimeUtc = $item.LastWriteTimeUtc.ToString("o")
            Length = $item.Length
            SHA256 = $hash
        }
    } else {
        $binaries[$bName] = [ordered]@{
            Exists = $false
            Path = $bPath
        }
    }
}
$evidence["Binaries"] = $binaries

# Windows Service Query
Write-Host "[PHASE 1] Querying Windows Service..." -ForegroundColor Yellow
$scQc = (sc.exe qc "SPEMCS Endpoint Agent" 2>&1 | Out-String).Trim()
$scQuery = (sc.exe query "SPEMCS Endpoint Agent" 2>&1 | Out-String).Trim()
$svc = Get-Service "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
$evidence["Service"] = [ordered]@{
    ScQc = $scQc
    ScQuery = $scQuery
    Status = if ($svc) { $svc.Status.ToString() } else { "NotFound" }
    StartType = if ($svc) { $svc.StartType.ToString() } else { "NotFound" }
}

# ImagePath from Registry
$regKey = "HKLM:\SYSTEM\CurrentControlSet\Services\SPEMCS Endpoint Agent"
if (Test-Path $regKey) {
    $evidence["Service"]["RegistryImagePath"] = (Get-ItemProperty -Path $regKey -Name ImagePath -ErrorAction SilentlyContinue).ImagePath
}

# ProgramData Config
Write-Host "[PHASE 1] Checking ProgramData config.json..." -ForegroundColor Yellow
$configCandidates = @(
    "C:\ProgramData\SPEMCS\Endpoint Agent\config.json",
    "C:\ProgramData\Spemcs\config.json"
)
$configData = [ordered]@{}
foreach ($cfg in $configCandidates) {
    if (Test-Path $cfg) {
        $cfgItem = Get-Item $cfg
        $content = [string](Get-Content $cfg -Raw)
        $configData[$cfg] = [ordered]@{
            Exists = $true
            LastWriteTimeUtc = $cfgItem.LastWriteTimeUtc.ToString("o")
            Content = $content
        }
    } else {
        $configData[$cfg] = [ordered]@{ Exists = $false }
    }
}
$evidence["Configs"] = $configData

# Running Processes
Write-Host "[PHASE 1] Checking Running Processes..." -ForegroundColor Yellow
$runningProcs = @()
foreach ($proc in (Get-Process -Name "Spemcs.Agent.Service", "Spemcs.Agent.UI" -ErrorAction SilentlyContinue)) {
    $procStartTime = "AccessDenied"
    try {
        $procStartTime = $proc.StartTime.ToUniversalTime().ToString("o")
    } catch {
        $procStartTime = "AccessDenied"
    }

    $procPath = "AccessDenied"
    try {
        $procPath = $proc.MainModule.FileName
    } catch {
        $procPath = "AccessDenied"
    }

    $pInfo = [ordered]@{
        Name = $proc.ProcessName
        Id = $proc.Id
        SessionId = $proc.SessionId
        StartTimeUtc = $procStartTime
        Path = $procPath
    }
    $runningProcs += $pInfo
}
$evidence["RunningProcesses"] = $runningProcs

# -------------------------------------------------------------
# PHASE 4 — VERIFY INTERACTIVE SESSION
# -------------------------------------------------------------
Write-Host "`n[PHASE 4] Checking Sessions..." -ForegroundColor Yellow
$querySession = (query session 2>&1 | Out-String).Trim()
$quserOut = (quser 2>&1 | Out-String).Trim()
$evidence["Sessions"] = [ordered]@{
    QuerySession = $querySession
    Quser = $quserOut
}

# P/Invoke WTS
if (-not ("WtsHelper" -as [type])) {
    Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class WtsHelper {
    [DllImport("kernel32.dll")] public static extern uint WTSGetActiveConsoleSessionId();
    [DllImport("wtsapi32.dll", SetLastError = true)] public static extern bool WTSQueryUserToken(uint sessionId, out IntPtr token);
    [DllImport("wtsapi32.dll", SetLastError = true)] public static extern bool WTSEnumerateSessions(IntPtr hServer, int reserved, int version, out IntPtr ppSessionInfo, out int pCount);
    [DllImport("wtsapi32.dll")] public static extern void WTSFreeMemory(IntPtr pMemory);
    [DllImport("kernel32.dll", SetLastError = true)] public static extern bool CloseHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    public struct WTS_SESSION_INFO {
        public int SessionId;
        public IntPtr pWinStationName;
        public int State;
    }
}
"@ -ErrorAction SilentlyContinue
}

$consoleSessionId = [WtsHelper]::WTSGetActiveConsoleSessionId()
$evidence["WTS"] = [ordered]@{
    ActiveConsoleSessionId = $consoleSessionId
}

$enumSessions = @()
$pInfo = [IntPtr]::Zero
$count = 0
if ([WtsHelper]::WTSEnumerateSessions([IntPtr]::Zero, 0, 1, [ref]$pInfo, [ref]$count)) {
    $structSize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][WtsHelper+WTS_SESSION_INFO])
    for ($i = 0; $i -lt $count; $i++) {
        $ptr = [IntPtr]::Add($pInfo, ($i * $structSize))
        $item = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ptr, [type][WtsHelper+WTS_SESSION_INFO])
        $wName = [System.Runtime.InteropServices.Marshal]::PtrToStringAnsi($item.pWinStationName)
        $enumSessions += [ordered]@{
            SessionId = $item.SessionId
            WinStationName = $wName
            State = $item.State
        }
    }
    [WtsHelper]::WTSFreeMemory($pInfo)
}
$evidence["WTS"]["EnumeratedSessions"] = $enumSessions

# -------------------------------------------------------------
# PHASE 2 & 5 — CAPTURE LOGS & TRACE MARKERS
# -------------------------------------------------------------
Write-Host "`n[PHASE 2] Collecting Recent Log Lines..." -ForegroundColor Yellow
$logDir = "C:\ProgramData\Spemcs\Logs"
$recentLogs = [ordered]@{}
if (Test-Path $logDir) {
    # Check latest agent log
    $latestAgentLog = Get-ChildItem -Path $logDir -Filter "agent-*.log" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($latestAgentLog) {
        $recentLogs["LatestAgentLog"] = $latestAgentLog.FullName
        $recentLogs["AgentLogTail"] = @(Get-Content $latestAgentLog.FullName -Tail 150 | ForEach-Object { [string]$_ })
    }
    # Check agent_service.log
    $asLog = Join-Path $logDir "agent_service.log"
    if (Test-Path $asLog) {
        $recentLogs["AgentServiceLogTail"] = @(Get-Content $asLog -Tail 150 | ForEach-Object { [string]$_ })
    }
    # Check agent_ui.log
    $auLog = Join-Path $logDir "agent_ui.log"
    if (Test-Path $auLog) {
        $recentLogs["AgentUiLogTail"] = @(Get-Content $auLog -Tail 150 | ForEach-Object { [string]$_ })
    }
    # Check msi_upgrade.log
    $msiLog = Join-Path $logDir "msi_upgrade.log"
    if (-not (Test-Path $msiLog)) {
        $altMsi = Get-ChildItem "C:\Windows\Temp" -Filter "MSI*.LOG" -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
        if ($altMsi) { $msiLog = $altMsi.FullName }
    }
    if (Test-Path $msiLog) {
        Write-Host "Found MSI log at $msiLog" -ForegroundColor Green
        $recentLogs["MsiLogPath"] = $msiLog
        $rawMsiLines = @(Get-Content -Path $msiLog | ForEach-Object { [string]$_ })
        $recentLogs["MsiLogTotalLines"] = $rawMsiLines.Count
        
        $ret3 = @()
        for ($i = 0; $i -lt $rawMsiLines.Count; $i++) {
            if ($rawMsiLines[$i] -match "Return value 3") {
                $ret3 += $i
            }
        }
        $recentLogs["MsiReturnVal3Indices"] = $ret3
        if ($ret3.Count -gt 0) {
            $idx = $ret3[0]
            $sIdx = [Math]::Max(0, $idx - 100)
            $eIdx = [Math]::Min($rawMsiLines.Count - 1, $idx + 50)
            $recentLogs["MsiFailingChunk"] = @($rawMsiLines[$sIdx..$eIdx])
        } else {
            $recentLogs["MsiFailingChunk"] = @($rawMsiLines | Select-Object -Last 100)
        }
        
        # Summary of MSI Actions
        $actSummary = @()
        for ($i = 0; $i -lt $rawMsiLines.Count; $i++) {
            $l = $rawMsiLines[$i]
            if ($l -match "Action start|Action ended|Error 1|Error 2|CustomAction|ServiceInstall|ServiceControl|StartServices|StopServices|DeleteServices|InstallServices|RemoveExistingProducts") {
                $actSummary += "$($i+1): $l"
            }
        }
        $recentLogs["MsiActionSummary"] = @($actSummary | Select-Object -Last 120)
    }
}
$evidence["Logs"] = $recentLogs

# Filter key markers across recent logs
$markersOfInterest = @(
    "UI_LAUNCH_REQUESTED", "UI_LAUNCH_BEGIN", "UI_SESSION_DISCOVERY", "UI_SESSION_SELECTED",
    "UI_TOKEN_ACQUIRED", "UI_TOKEN_DUPLICATED", "UI_ENVIRONMENT_CREATED", "UI_PROCESS_CREATE_BEGIN",
    "UI_PROCESS_CREATE_SUCCESS", "UI_PROCESS_CREATE_FAILED", "UI_LAUNCHED", "UI_PROCESS_START",
    "UI_MUTEX_ACQUIRED", "UI_APP_INITIALIZED", "UI_PIPE_WAIT_BEGIN", "UI_PIPE_CONNECTED",
    "PRECOMPLIANCE_SHOWN", "UI_LAUNCH_FAILED", "EXAM_PIPELINE_FAILED", "EXAM_ACTIVATION_RECEIVED",
    "LAUNCH_EXAM_MODE_RECEIVED"
)

$foundMarkers = @()
if (Test-Path $logDir) {
    $recentLogFiles = Get-ChildItem -Path $logDir -Filter "*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 5
    if ($recentLogFiles) {
        $markerPattern = ($markersOfInterest -join "|")
        $targetPaths = @($recentLogFiles | ForEach-Object { $_.FullName })
        $hits = Select-String -Path $targetPaths -Pattern $markerPattern -ErrorAction SilentlyContinue | Select-Object -Last 100
        foreach ($h in $hits) {
            $foundMarkers += [ordered]@{
                Marker = if ($h.Matches.Count -gt 0) { $h.Matches[0].Value } else { "Marker" }
                File = Split-Path -Leaf $h.Path
                LineNumber = $h.LineNumber
                Line = $h.Line.Trim()
            }
        }
    }
}
$evidence["MarkersFound"] = $foundMarkers

# -------------------------------------------------------------
# PHASE 3 — WINDOWS EVENT LOG CORRELATION
# -------------------------------------------------------------
Write-Host "`n[PHASE 3] Checking Windows Event Logs (past 1 hour)..." -ForegroundColor Yellow
$since = (Get-Date).AddHours(-1)
$eventsApp = Get-WinEvent -FilterHashtable @{LogName='Application'; StartTime=$since} -ErrorAction SilentlyContinue |
    Where-Object { $_.ProviderName -match 'Spemcs|Runtime|Application Error|Windows Error Reporting|SideBySide|MsiInstaller' -or $_.Message -match 'Spemcs' } |
    Select-Object -First 30 |
    ForEach-Object {
        [ordered]@{
            TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
            Id = $_.Id
            ProviderName = $_.ProviderName
            LevelDisplayName = $_.LevelDisplayName
            Message = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
        }
    }
$evidence["EventLog_Application"] = $eventsApp

$eventsSys = Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Service Control Manager'; StartTime=$since} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match 'SPEMCS' } |
    Select-Object -First 10 |
    ForEach-Object {
        [ordered]@{
            TimeCreated = $_.TimeCreated.ToUniversalTime().ToString("o")
            Id = $_.Id
            LevelDisplayName = $_.LevelDisplayName
            Message = $_.Message.Substring(0, [Math]::Min(300, $_.Message.Length))
        }
    }
$evidence["EventLog_System"] = $eventsSys

# -------------------------------------------------------------
# PHASE 8 — NAMED PIPE STATUS
# -------------------------------------------------------------
Write-Host "`n[PHASE 8] Checking Named Pipes..." -ForegroundColor Yellow
$pipes = [System.IO.Directory]::GetFiles('\\.\pipe\') | Where-Object { $_ -match 'spemcs' }
$evidence["NamedPipes"] = $pipes

# -------------------------------------------------------------
# EMIT OUTPUT & POST TO CENTRAL SERVER
# -------------------------------------------------------------
$jsonOutput = $evidence | ConvertTo-Json -Depth 6

# Save locally
$localReportFile = "C:\ProgramData\Spemcs\Logs\pc06_forensic_report.json"
$localReportDir = [System.IO.Path]::GetDirectoryName($localReportFile)
if (-not (Test-Path $localReportDir)) {
    New-Item -ItemType Directory -Path $localReportDir -Force | Out-Null
}
Set-Content -Path $localReportFile -Value $jsonOutput -Force
Write-Host "`n[SAVED] Forensic report saved locally to $localReportFile" -ForegroundColor Green

# Post to central server
$centralUrl = "http://192.168.11.65:8000/deployment/traffic-test-results"
Write-Host "[UPLOADING] Uploading report to $centralUrl..." -ForegroundColor Yellow
try {
    $res = Invoke-RestMethod -Uri $centralUrl -Method Post -Body $jsonOutput -ContentType "application/json" -TimeoutSec 10
    Write-Host "[UPLOAD SUCCESS] Central server acknowledged report: $($res.status)" -ForegroundColor Green
} catch {
    Write-Host "[UPLOAD FAILED] Could not reach central server ($($_.Exception.Message)). Local report is preserved." -ForegroundColor Red
}

$svcBin = $binaries['Spemcs.Agent.Service.exe']
$uiBin = $binaries['Spemcs.Agent.UI.exe']
$svcVer = if ($svcBin.Contains("FileVersion")) { $svcBin["FileVersion"] } else { "NotFound" }
$svcHash = if ($svcBin.Contains("SHA256")) { $svcBin["SHA256"] } else { "NotFound" }
$uiVer = if ($uiBin.Contains("FileVersion")) { $uiBin["FileVersion"] } else { "NotFound" }
$uiHash = if ($uiBin.Contains("SHA256")) { $uiBin["SHA256"] } else { "NotFound" }
$svcStatusStr = if ($svc) { $svc.Status.ToString() } else { "NotFound" }

Write-Host "`n================== FORENSIC SUMMARY ==================" -ForegroundColor Cyan
Write-Host "Service Exe: $svcVer | Hash: $svcHash"
Write-Host "UI Exe:      $uiVer | Hash: $uiHash"
Write-Host "Console Session: $consoleSessionId | Sessions: $($enumSessions.Count)"
Write-Host "Service State: $svcStatusStr"
Write-Host "Running Processes: $(($runningProcs | ForEach-Object { "$($_.Name)(PID $($_.Id), Session $($_.SessionId))" }) -join ', ')"
Write-Host "Markers Recorded: $($foundMarkers.Count)"
Write-Host "======================================================" -ForegroundColor Cyan
