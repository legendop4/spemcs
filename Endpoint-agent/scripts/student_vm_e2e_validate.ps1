<#
.SYNOPSIS
    SPEMCS Endpoint Agent MSI E2E Validation Script for Windows Student VM.
    Executes all 22 verification criteria specified for real VM testing.
#>

param(
    [string]$MsiPath = "",
    [string]$ReportPath = ""
)

$ErrorActionPreference = "Continue"

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SPEMCS Windows Student VM MSI E2E Installation Validation " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

# Locate MSI
if (-not $MsiPath -or -not (Test-Path $MsiPath)) {
    $candidatePaths = @(
        "$PSScriptRoot\Endpoint-agent\installer\dist\Spemcs.Agent.Setup.msi",
        "$PWD\Endpoint-agent\installer\dist\Spemcs.Agent.Setup.msi",
        "\\vmware-host\Shared Folders\spemcs\Endpoint-agent\installer\dist\Spemcs.Agent.Setup.msi",
        "Z:\Endpoint-agent\installer\dist\Spemcs.Agent.Setup.msi",
        "C:\Windows\Temp\Spemcs.Agent.Setup.msi"
    )
    foreach ($cand in $candidatePaths) {
        if (Test-Path $cand) {
            $MsiPath = $cand
            break
        }
    }
}

if (-not $MsiPath -or -not (Test-Path $MsiPath)) {
    Write-Error "MSI package not found! Looked in candidate paths. Specify -MsiPath <path>"
    exit 1
}

$msiItem = Get-Item $MsiPath
Write-Host "Target MSI: $($msiItem.FullName) (Size: $($msiItem.Length) bytes)" -ForegroundColor Green

# Local copy to avoid UNC path issues with msiexec
$localMsi = "C:\Windows\Temp\Spemcs.Agent.Setup.msi"
if ((Resolve-Path $MsiPath).Path -ne (Resolve-Path $localMsi -ErrorAction SilentlyContinue).Path) {
    Copy-Item -Path $MsiPath -Destination $localMsi -Force
}

if (-not $ReportPath) {
    $ReportPath = "$PSScriptRoot\vm_validation_report.json"
}

$results = [ordered]@{}

function Set-ItemResult($id, $title, $pass, $evidence) {
    $status = if ($pass) { "PASS" } else { "FAIL" }
    $color = if ($pass) { "Green" } else { "Red" }
    Write-Host "[$status] Item ${id}: $title" -ForegroundColor $color
    Write-Host "       Evidence: $evidence" -ForegroundColor Gray
    $results["Item_$id"] = [ordered]@{
        Id = $id
        Title = $title
        Status = $status
        Evidence = $evidence
    }
}

# ============================================================
# PHASE 1: PRE-INSTALLATION CAPTURE
# ============================================================
Write-Host "`n--- Phase 1: Pre-Installation Capture ---" -ForegroundColor Yellow

$preInstall = [ordered]@{}

# 1. Installed SPEMCS version
$regKey = Get-ItemProperty "HKLM:\SOFTWARE\SPEMCS\EndpointAgent" -ErrorAction SilentlyContinue
$uninstallKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -like "*SPEMCS*" }
$preInstall["InstalledVersionRegistry"] = if ($regKey) { $regKey.SeenVersion } else { "None" }
$preInstall["UninstallEntry"] = if ($uninstallKey) { "$($uninstallKey.DisplayName) ($($uninstallKey.DisplayVersion))" } else { "None" }
Write-Host "Pre-install Version: $($preInstall["InstalledVersionRegistry"]) / $($preInstall["UninstallEntry"])"

# 2. Existing service state
$svc = Get-Service -Name "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
$preInstall["ServiceExists"] = ($null -ne $svc)
$preInstall["ServiceStatus"] = if ($svc) { $svc.Status.ToString() } else { "Not Installed" }
Write-Host "Pre-install Service State: $($preInstall["ServiceStatus"])"

# 3. Program Files\SPEMCS\Endpoint Agent contents
$progFilesPath = "C:\Program Files\SPEMCS\Endpoint Agent"
$preInstall["ProgramFilesExists"] = (Test-Path $progFilesPath)
$preInstall["ProgramFilesItems"] = if (Test-Path $progFilesPath) { (Get-ChildItem -Path $progFilesPath -Recurse | Select-Object -ExpandProperty FullName) } else { @() }
Write-Host "Pre-install Program Files Item Count: $(($preInstall["ProgramFilesItems"]).Count)"

# 4. ProgramData\Spemcs state
$progDataPath = "C:\ProgramData\Spemcs"
$preInstall["ProgramDataExists"] = (Test-Path $progDataPath)
$preInstall["ProgramDataItems"] = if (Test-Path $progDataPath) { (Get-ChildItem -Path $progDataPath -Recurse | Select-Object -ExpandProperty FullName) } else { @() }
Write-Host "Pre-install ProgramData Item Count: $(($preInstall["ProgramDataItems"]).Count)"

# Baseline Firewall Rules
$baselineFwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$preInstall["BaselineFirewallRuleCount"] = $baselineFwRules.Count
Write-Host "Pre-install Firewall Rules Count: $($baselineFwRules.Count)"

$results["PreInstallationCapture"] = $preInstall

# ============================================================
# PHASE 2: MSI INSTALLATION
# ============================================================
Write-Host "`n--- Phase 2: MSI Installation ---" -ForegroundColor Yellow
$installLog = "C:\Windows\Temp\spemcs_install.log"
if (Test-Path $installLog) { Remove-Item $installLog -Force }

$installStartTime = Get-Date

Write-Host "Launching msiexec /i `"$localMsi`" /qn /l*v `"$installLog`"..." -ForegroundColor Gray
$proc = Start-Process msiexec.exe -ArgumentList "/i `"$localMsi`" /qn /l*v `"$installLog`"" -Wait -PassThru
$installExitCode = $proc.ExitCode

$msiSuccessInLog = $false
if (Test-Path $installLog) {
    $msiSuccessInLog = [bool](Select-String -Path $installLog -Pattern "Product: SPEMCS Endpoint Agent -- Installation completed successfully\.|MainEngineThread is returning 0")
}

# Item 1: MSI installation succeeds
$item1Pass = ($installExitCode -eq 0 -or $installExitCode -eq 3010) -and $msiSuccessInLog
Set-ItemResult 1 "MSI installation succeeds" $item1Pass "ExitCode: $installExitCode, Success in log: $msiSuccessInLog"

# Wait a couple seconds for service launch
Start-Sleep -Seconds 3

# ============================================================
# PHASE 3: POST-INSTALLATION SERVICE & FILE VERIFICATION
# ============================================================
Write-Host "`n--- Phase 3: Post-Installation Verification ---" -ForegroundColor Yellow

# Item 2: SPEMCS Endpoint Agent exists in SCM
$svc = Get-Service -Name "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
$item2Pass = ($null -ne $svc)
Set-ItemResult 2 "'SPEMCS Endpoint Agent' exists in SCM" $item2Pass "Service Name: $($svc.Name), Display: $($svc.DisplayName)"

# Item 3: Service executable path is correct
$svcCim = Get-CimInstance Win32_Service -Filter "Name='SPEMCS Endpoint Agent'" -ErrorAction SilentlyContinue
$expectedBinPath = "C:\Program Files\SPEMCS\Endpoint Agent\Spemcs.Agent.Service.exe"
$actualPath = if ($svcCim) { $svcCim.PathName.Trim('"') } else { "None" }
$item3Pass = ($actualPath -eq $expectedBinPath)
Set-ItemResult 3 "Service executable path is correct" $item3Pass "PathName: $actualPath"

# Item 4: Service is LocalSystem
$actualAccount = if ($svcCim) { $svcCim.StartName } else { "None" }
$item4Pass = ($actualAccount -eq "LocalSystem" -or $actualAccount -eq "NT AUTHORITY\LocalSystem")
Set-ItemResult 4 "Service is LocalSystem" $item4Pass "StartName: $actualAccount"

# Item 5: Startup type is Automatic
$actualStartMode = if ($svcCim) { $svcCim.StartMode } else { "None" }
$item5Pass = ($actualStartMode -eq "Auto")
Set-ItemResult 5 "Startup type is Automatic" $item5Pass "StartMode: $actualStartMode"

# Item 6: Service starts successfully
$svc = Get-Service -Name "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -ne "Running") {
    Start-Service -Name "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $svc.Refresh()
}
$item6Pass = ($svc -and $svc.Status -eq "Running")
Set-ItemResult 6 "Service starts successfully" $item6Pass "Status: $($svc.Status)"

# Item 7: Service remains Running for at least an observation period (15s)
Write-Host "Observing service running state over 15 seconds..." -ForegroundColor Gray
$runningObservations = 0
for ($i = 0; $i -lt 5; $i++) {
    Start-Sleep -Seconds 3
    $svc.Refresh()
    if ($svc.Status -eq "Running") { $runningObservations++ }
}
$item7Pass = ($runningObservations -eq 5)
Set-ItemResult 7 "Service remains Running for observation period" $item7Pass "Successful Running checks: $runningObservations / 5 over 15s"

# Item 8: System.ServiceProcess.ServiceController.dll exists at expected runtime path
$svcCtrlPath = "C:\Program Files\SPEMCS\Endpoint Agent\runtimes\win\lib\net8.0\System.ServiceProcess.ServiceController.dll"
$item8Pass = (Test-Path $svcCtrlPath)
$svcCtrlSize = if ($item8Pass) { (Get-Item $svcCtrlPath).Length } else { 0 }
Set-ItemResult 8 "System.ServiceProcess.ServiceController.dll exists at expected runtime path" $item8Pass "Path: $svcCtrlPath (Size: $svcCtrlSize bytes)"

# Item 9: All critical runtime dependencies are physically present
$critFiles = @(
    "C:\Program Files\SPEMCS\Endpoint Agent\Spemcs.Agent.Service.exe",
    "C:\Program Files\SPEMCS\Endpoint Agent\Spemcs.Agent.UI.exe",
    "C:\Program Files\SPEMCS\Endpoint Agent\Spemcs.Agent.Service.dll",
    "C:\Program Files\SPEMCS\Endpoint Agent\Spemcs.Agent.UI.dll",
    "C:\Program Files\SPEMCS\Endpoint Agent\Spemcs.Agent.Core.dll",
    "C:\Program Files\SPEMCS\Endpoint Agent\Spemcs.Agent.Ipc.dll",
    "C:\Program Files\SPEMCS\Endpoint Agent\runtimes\win-x64\native\e_sqlite3.dll",
    "C:\ProgramData\Spemcs\Endpoint Agent\config.template.json"
)
$missingFiles = @()
foreach ($f in $critFiles) {
    if (-not (Test-Path $f)) { $missingFiles += $f }
}
$item9Pass = ($missingFiles.Count -eq 0)
$item9Evidence = if ($item9Pass) { "All $($critFiles.Count) files verified present on disk" } else { "Missing: $($missingFiles -join ', ')" }
Set-ItemResult 9 "All critical runtime dependencies physically present" $item9Pass $item9Evidence

# Item 10: No .NET Runtime Event ID 1026 occurs
$events1026 = Get-WinEvent -FilterHashtable @{LogName='Application'; Id=1026; StartTime=$installStartTime} -ErrorAction SilentlyContinue
$item10Pass = ($null -eq $events1026 -or $events1026.Count -eq 0)
Set-ItemResult 10 "No .NET Runtime Event ID 1026 occurs" $item10Pass "Found: $(if ($events1026) { $events1026.Count } else { 0 }) events"

# Item 11: No SCM 7000/7009 startup failure occurs
$eventsScm = Get-WinEvent -FilterHashtable @{LogName='System'; Id=7000,7009; StartTime=$installStartTime} -ErrorAction SilentlyContinue | Where-Object { $_.Message -like "*SPEMCS*" }
$item11Pass = ($null -eq $eventsScm -or $eventsScm.Count -eq 0)
Set-ItemResult 11 "No SCM 7000/7009 startup failure occurs" $item11Pass "Found: $(if ($eventsScm) { $eventsScm.Count } else { 0 }) events"

# Item 12: UI executable launches
$existingUi = Get-Process -Name "Spemcs.Agent.UI" -ErrorAction SilentlyContinue
if ($existingUi) {
    Set-ItemResult 12 "UI executable launches" $true "UI process already running from MSI first-run action (PID: $($existingUi.Id))"
} else {
    $uiPath = "C:\Program Files\SPEMCS\Endpoint Agent\Spemcs.Agent.UI.exe"
    $uiProc = Start-Process -FilePath $uiPath -PassThru -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 3
    $uiRunning = ($uiProc -and -not $uiProc.HasExited)
    if ($uiProc -and -not $uiProc.HasExited) {
        Stop-Process -Id $uiProc.Id -Force -ErrorAction SilentlyContinue
    }
    Set-ItemResult 12 "UI executable launches" $uiRunning "PID: $($uiProc.Id), Running after 3s: $uiRunning"
}

# Network diagnostics
$localVMIps = (Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -notlike "127.*" }).IPAddress -join ", "
Write-Host "Student VM local IPv4 addresses: $localVMIps" -ForegroundColor Gray

# Item 13: Agent can reach backend 192.168.91.1:8002
$backendReachable = $false
$healthResponse = ""
$targetHosts = @("192.168.91.1", "192.168.27.1")
foreach ($tHost in $targetHosts) {
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient
        $iar = $tcp.BeginConnect($tHost, 8002, $null, $null)
        $wait = $iar.AsyncWaitHandle.WaitOne(3000, $false)
        if ($wait -and $tcp.Connected) {
            $tcp.EndConnect($iar)
            $tcp.Close()
            $resp = Invoke-RestMethod -Uri "http://${tHost}:8002/api/v1/management/health" -TimeoutSec 5 -ErrorAction Stop
            if ($resp.status -eq "ok") {
                $backendReachable = $true
                $healthResponse = "Host ${tHost}: $($resp | ConvertTo-Json -Compress)"
                break
            } else {
                $healthResponse = "Host ${tHost}: status not ok"
            }
        } else {
            $tcp.Close()
            $healthResponse = "Host ${tHost}: TCP connection timeout/refused"
        }
    } catch {
        $healthResponse = "Host ${tHost} error: $($_.Exception.Message)"
    }
}
Set-ItemResult 13 "Agent can reach backend 192.168.91.1:8002" $backendReachable "Local IPs: [$localVMIps] | Result: $healthResponse"

# Item 14: Enrollment/registration state remains functional
$labFetchStatus = ""
$enrollmentFunctional = $false
foreach ($tHost in $targetHosts) {
    # Check live enrollment endpoint per API contract (/api/v1/enrollment/labs)
    try {
        $labs = Invoke-RestMethod -Uri "http://${tHost}:8002/api/v1/enrollment/labs" -TimeoutSec 5 -ErrorAction Stop
        $enrollmentFunctional = $true
        $labFetchStatus = "Host ${tHost} returned labs (HTTP 200)"
        break
    } catch {
        $statusCode = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { 0 }
        if ($statusCode -eq 401 -or $_.Exception.Message -match "401|Unauthorized") {
            $enrollmentFunctional = $true
            $labFetchStatus = "Host ${tHost}: HTTP 401 Unauthorized as expected without enrollment key"
            break
        } else {
            $labFetchStatus = "Host ${tHost}: $($_.Exception.Message)"
        }
    }
}
# Also verify local agent enrollment state persistence
$agentDbExists = Test-Path "C:\ProgramData\Spemcs\agent.db"
$configJsonExists = Test-Path "C:\ProgramData\Spemcs\Endpoint Agent\config.json"
$enrollmentEvidence = "API: $labFetchStatus | agent.db: $agentDbExists | config.json: $configJsonExists"
Set-ItemResult 14 "Enrollment/registration state remains functional" ($enrollmentFunctional -and $agentDbExists) $enrollmentEvidence

# Item 15 & 16: Verify MSI installation did NOT create/modify firewall rules
$postInstallFwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$addedRules = $postInstallFwRules | Where-Object { $baselineFwRules -notcontains $_ }
$spemcsFwRules = $postInstallFwRules | Where-Object { $_ -like "*SPEMCS*" }
$item15Pass = ($spemcsFwRules.Count -eq 0)
$item16Pass = ($addedRules.Count -eq 0)
Set-ItemResult 15 "Verify MSI installation did NOT create/modify firewall rules" $item15Pass "SPEMCS firewall rules: $(if ($spemcsFwRules) { $spemcsFwRules.Count } else { 0 })"
Set-ItemResult 16 "Verify no unrelated firewall rule was modified" $item16Pass "Rules added during MSI install: $(if ($addedRules) { $addedRules.Count } else { 0 })"

# ============================================================
# PHASE 4: UNINSTALL E2E
# ============================================================
Write-Host "`n--- Phase 4: Uninstall E2E ---" -ForegroundColor Yellow
$uninstallLog = "C:\Windows\Temp\spemcs_uninstall.log"
if (Test-Path $uninstallLog) { Remove-Item $uninstallLog -Force }

$uProc = Start-Process msiexec.exe -ArgumentList "/x `"$localMsi`" /qn /l*v `"$uninstallLog`"" -Wait -PassThru
$uninstallExitCode = $uProc.ExitCode

$item17Pass = ($uninstallExitCode -eq 0 -or $uninstallExitCode -eq 3010)
Set-ItemResult 17 "Uninstall MSI succeeds" $item17Pass "ExitCode: $uninstallExitCode"

Start-Sleep -Seconds 3

# Item 18: Verify service removal
$svcAfterUninstall = Get-Service -Name "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
$item18Pass = ($null -eq $svcAfterUninstall)
Set-ItemResult 18 "Verify service removal from SCM" $item18Pass "Service exists: $($null -ne $svcAfterUninstall)"

# Item 19: Verify expected application files are removed
$progFilesRemaining = if (Test-Path "C:\Program Files\SPEMCS\Endpoint Agent") {
    (Get-ChildItem -Path "C:\Program Files\SPEMCS\Endpoint Agent" -Recurse | Select-Object -ExpandProperty FullName)
} else { @() }
$item19Pass = ($progFilesRemaining.Count -eq 0)
Set-ItemResult 19 "Verify expected application files are removed" $item19Pass "Remaining files count: $($progFilesRemaining.Count)"

# Item 20: Verify ProgramData persistence/deletion matches contract
$templateRemoved = -not (Test-Path "C:\ProgramData\Spemcs\Endpoint Agent\config.template.json")
$item20Pass = $templateRemoved
Set-ItemResult 20 "Verify ProgramData matches contract (template removed)" $item20Pass "Template removed: $templateRemoved"

# Item 21: Verify no firewall mutation during uninstall
$postUninstallFwRules = Get-NetFirewallRule -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name
$fwDiff = $postUninstallFwRules | Where-Object { $baselineFwRules -notcontains $_ }
$item21Pass = ($fwDiff.Count -eq 0)
Set-ItemResult 21 "Verify no firewall mutation during uninstall" $item21Pass "Diff rule count: $($fwDiff.Count)"

# ============================================================
# PHASE 5: REINSTALL E2E
# ============================================================
Write-Host "`n--- Phase 5: Reinstall Verification ---" -ForegroundColor Yellow
$reinstallProc = Start-Process msiexec.exe -ArgumentList "/i `"$localMsi`" /qn" -Wait -PassThru
Start-Sleep -Seconds 3

$reinstalledSvc = Get-Service -Name "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
if ($reinstalledSvc -and $reinstalledSvc.Status -ne "Running") {
    Start-Service -Name "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $reinstalledSvc.Refresh()
}
$item22Pass = ($reinstallProc.ExitCode -eq 0 -and $reinstalledSvc -and $reinstalledSvc.Status -eq "Running")
Set-ItemResult 22 "Reinstall MSI once and verify service starts again" $item22Pass "ExitCode: $($reinstallProc.ExitCode), Service Status: $($reinstalledSvc.Status)"

# Final Summary
Write-Host "`n============================================================" -ForegroundColor Cyan
Write-Host " Validation Complete: Saving Reports " -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

$allPass = $true
foreach ($k in $results.Keys) {
    if ($k -like "Item_*") {
        if ($results[$k].Status -ne "PASS") { $allPass = $false }
    }
}
$results["OverallStatus"] = if ($allPass) { "ALL_PASS" } else { "SOME_FAILED" }
$results["Timestamp"] = (Get-Date).ToString("o")

$json = $results | ConvertTo-Json -Depth 5

$candidateReportPaths = @(
    $ReportPath,
    "$PSScriptRoot\vm_validation_report.json",
    "\\vmware-host\Shared Folders\spemcs\vm_validation_report.json",
    "C:\Windows\Temp\vm_validation_report.json"
)

foreach ($rp in $candidateReportPaths) {
    try {
        Set-Content -Path $rp -Value $json -Force -ErrorAction SilentlyContinue
        Write-Host "Saved JSON report to: $rp" -ForegroundColor Green
    } catch { }
}

Write-Host "`nALL 22 ITEMS TESTED. Overall Status: $($results["OverallStatus"])" -ForegroundColor $(if ($allPass) { "Green" } else { "Red" })
