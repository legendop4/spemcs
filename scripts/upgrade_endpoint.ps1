# SPEMCS Endpoint Agent Automated Upgrade Script
$ErrorActionPreference = "Continue"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   SPEMCS ENDPOINT AGENT LIVE UPGRADE (v2.2.8.0 FIX)      " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 0. Check Elevation
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "`n[FATAL ERROR] This upgrade script MUST be run in an ELEVATED PowerShell window!" -ForegroundColor Red
    Write-Host "Action Required: Open PowerShell using 'Run as Administrator' on this machine and re-run." -ForegroundColor Yellow
    exit 1
}

$serverBase = "http://192.168.11.65:8000"
$msiUrl = "$serverBase/deployment/download"
$expectedHash = "03A309428A44C438D237E4675869B45C400023D66734E4AEAA1A1BD284008943"
$tempMsi = "C:\Windows\Temp\Spemcs.Agent.Setup.msi"
$msiLog = "C:\ProgramData\Spemcs\Logs\msi_upgrade.log"

# 1. Download MSI
Write-Host "`n[1/5] Downloading latest MSI from $msiUrl..." -ForegroundColor Yellow
try {
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($msiUrl, $tempMsi)
    Write-Host "MSI downloaded successfully to $tempMsi" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Failed to download MSI: $($_.Exception.Message)" -ForegroundColor Red
    exit 1
}

# 2. Verify Hash
Write-Host "`n[2/5] Verifying MSI SHA256..." -ForegroundColor Yellow
$actualHash = (Get-FileHash -Path $tempMsi -Algorithm SHA256).Hash
Write-Host "Expected: $expectedHash"
Write-Host "Actual:   $actualHash"
if ($actualHash -ne $expectedHash) {
    Write-Host "[ERROR] MSI SHA256 hash mismatch! Aborting." -ForegroundColor Red
    exit 1
}
Write-Host "[VERIFIED] SHA256 matches expected build artifact." -ForegroundColor Green

# 3. Kill any lingering UI processes & gracefully stop service
Write-Host "`n[3/5] Stopping lingering agent processes..." -ForegroundColor Yellow
Get-Process -Name "Spemcs.Agent.UI" -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
Stop-Service -Name "SPEMCS Endpoint Agent" -Force -ErrorAction SilentlyContinue

# 3.5 Disarm legacy cached MSI ServiceControl defect (prevents Error 1920 on RemoveExistingProducts)
Write-Host "`n[3.5/5] Scanning for legacy cached MSI packages to disarm..." -ForegroundColor Yellow
try {
    $installerObj = New-Object -ComObject WindowsInstaller.Installer
    $cachedMsiList = @()

    # Query registered packages via WindowsInstaller COM
    try {
        $allProds = $installerObj.GetType().InvokeMember('Products', 'GetProperty', $null, $installerObj, $null)
        foreach ($pCode in $allProds) {
            try {
                $pName = $installerObj.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installerObj, @($pCode, 'ProductName'))
                if ($pName -match 'SPEMCS') {
                    $pkg = $installerObj.GetType().InvokeMember('ProductInfo', 'GetProperty', $null, $installerObj, @($pCode, 'LocalPackage'))
                    if ($pkg -and (Test-Path $pkg)) {
                        $cachedMsiList += $pkg
                    }
                }
            } catch {}
        }
    } catch {}

    # Query registered packages via Registry UserData
    $regBase = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Installer\UserData\S-1-5-18\Products"
    if (Test-Path $regBase) {
        Get-ChildItem -Path $regBase -ErrorAction SilentlyContinue | ForEach-Object {
            $propKey = Join-Path $_.PSPath "InstallProperties"
            if (Test-Path $propKey) {
                $props = Get-ItemProperty -Path $propKey -ErrorAction SilentlyContinue
                if ($props.DisplayName -like "*SPEMCS*") {
                    if ($props.LocalPackage -and (Test-Path $props.LocalPackage)) {
                        $cachedMsiList += $props.LocalPackage
                    }
                }
            }
        }
    }

    $uniquePkgs = $cachedMsiList | Select-Object -Unique
    if ($uniquePkgs -and $uniquePkgs.Count -gt 0) {
        Write-Host "Found $($uniquePkgs.Count) cached SPEMCS MSI package(s) on system:" -ForegroundColor Yellow
        foreach ($pkgPath in $uniquePkgs) {
            Write-Host "  -> Inspecting & disarming $pkgPath..." -ForegroundColor Gray
            try {
                $patched = $false
                # Take ownership & grant Administrators full control if restricted
                & takeown /f "$pkgPath" /a 2>&1 | Out-Null
                & icacls "$pkgPath" /grant "Administrators:F" 2>&1 | Out-Null
                try { Set-ItemProperty -Path $pkgPath -Name IsReadOnly -Value $false -ErrorAction Stop } catch {}

                # Strategy A: Direct in-place transactional update
                try {
                    $cachedDb = $installerObj.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installerObj, @([string]$pkgPath, 1))
                    $scSql = "UPDATE `ServiceControl` SET `Event` = 163 WHERE `Name` = 'SPEMCS Endpoint Agent'"
                    $scView = $cachedDb.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $cachedDb, @($scSql))
                    $scView.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $scView, $null)
                    $scView.GetType().InvokeMember('Close', 'InvokeMethod', $null, $scView, $null)
                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($scView) | Out-Null

                    $iesSql = "UPDATE `InstallExecuteSequence` SET `Condition` = 'VersionNT AND NOT REMOVE~=""ALL""' WHERE `Action` = 'StartServices'"
                    $iesView = $cachedDb.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $cachedDb, @($iesSql))
                    $iesView.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $iesView, $null)
                    $iesView.GetType().InvokeMember('Close', 'InvokeMethod', $null, $iesView, $null)
                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($iesView) | Out-Null

                    $cachedDb.GetType().InvokeMember('Commit', 'InvokeMethod', $null, $cachedDb, $null)
                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($cachedDb) | Out-Null
                    $patched = $true
                    Write-Host "  [DISARMED] Direct in-place update succeeded for $pkgPath" -ForegroundColor Green
                } catch {
                    Write-Host "  [INFO] In-place direct update bypassed ($($_.Exception.Message)). Trying staged patch..." -ForegroundColor Gray
                }

                # Strategy B: Staged copy update
                if (-not $patched) {
                    $tempMsiCopy = [System.IO.Path]::GetTempFileName() + ".msi"
                    Copy-Item -Path $pkgPath -Destination $tempMsiCopy -Force
                    try { Set-ItemProperty -Path $tempMsiCopy -Name IsReadOnly -Value $false -ErrorAction Stop } catch {}

                    $tempDb = $installerObj.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installerObj, @([string]$tempMsiCopy, 1))
                    $scSql = "UPDATE `ServiceControl` SET `Event` = 163 WHERE `Name` = 'SPEMCS Endpoint Agent'"
                    $scView = $tempDb.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $tempDb, @($scSql))
                    $scView.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $scView, $null)
                    $scView.GetType().InvokeMember('Close', 'InvokeMethod', $null, $scView, $null)
                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($scView) | Out-Null

                    $iesSql = "UPDATE `InstallExecuteSequence` SET `Condition` = 'VersionNT AND NOT REMOVE~=""ALL""' WHERE `Action` = 'StartServices'"
                    $iesView = $tempDb.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $tempDb, @($iesSql))
                    $iesView.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $iesView, $null)
                    $iesView.GetType().InvokeMember('Close', 'InvokeMethod', $null, $iesView, $null)
                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($iesView) | Out-Null

                    $tempDb.GetType().InvokeMember('Commit', 'InvokeMethod', $null, $tempDb, $null)
                    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($tempDb) | Out-Null
                    [System.GC]::Collect()
                    [System.GC]::WaitForPendingFinalizers()

                    Copy-Item -Path $tempMsiCopy -Destination $pkgPath -Force
                    Remove-Item -Path $tempMsiCopy -Force -ErrorAction SilentlyContinue
                    Write-Host "  [DISARMED] Staged copy update succeeded for $pkgPath" -ForegroundColor Green
                }
            } catch {
                Write-Host "  [NOTICE] Could not patch $($pkgPath): $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    } else {
        Write-Host "No cached legacy SPEMCS packages detected." -ForegroundColor Green
    }

    [System.Runtime.InteropServices.Marshal]::ReleaseComObject($installerObj) | Out-Null
    [System.GC]::Collect()
    [System.GC]::WaitForPendingFinalizers()
} catch {
    Write-Host "Legacy check warning: $($_.Exception.Message)" -ForegroundColor Yellow
}

# 4. Execute MSI Install / Upgrade
Write-Host "`n[4/5] Executing MSI Upgrade (logging to $msiLog)..." -ForegroundColor Yellow
$proc = Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$tempMsi`" /qn /norestart /l*v `"$msiLog`"" -Wait -PassThru
Write-Host "MSI process exited with code: $($proc.ExitCode)"

if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
    Write-Host "[ERROR] MSI installation failed with exit code $($proc.ExitCode)!" -ForegroundColor Red
    if (Test-Path $msiLog) {
        Write-Host "`n--- Tail of MSI Log ($msiLog) ---" -ForegroundColor Yellow
        Get-Content $msiLog -Tail 25
    }
    exit $proc.ExitCode
}

# 5. Service Check & Restart
Write-Host "`n[5/5] Ensuring SPEMCS Service is running..." -ForegroundColor Yellow
$svc = Get-Service "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
if ($svc) {
    if ($svc.Status -ne "Running") {
        Write-Host "Starting service..." -ForegroundColor Yellow
        Start-Service "SPEMCS Endpoint Agent" -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    $svc = Get-Service "SPEMCS Endpoint Agent"
    Write-Host "Service Status: $($svc.Status)" -ForegroundColor Green
} else {
    Write-Host "[ERROR] SPEMCS Endpoint Agent service not found!" -ForegroundColor Red
}

# Verification of installed binaries
$installFolder = "C:\Program Files\SPEMCS\Endpoint Agent"
$serviceExe = Join-Path $installFolder "Spemcs.Agent.Service.exe"
$uiExe = Join-Path $installFolder "Spemcs.Agent.UI.exe"

Write-Host "`n================ INSTALLED BINARY VERIFICATION ================" -ForegroundColor Cyan
if (Test-Path $serviceExe) {
    $sHash = (Get-FileHash $serviceExe -Algorithm SHA256).Hash
    $sVer = (Get-Item $serviceExe).VersionInfo.FileVersion
    Write-Host "Service Exe: $sVer | SHA256: $sHash" -ForegroundColor Green
} else {
    Write-Host "Service Exe: NOT FOUND" -ForegroundColor Red
}

if (Test-Path $uiExe) {
    $uHash = (Get-FileHash $uiExe -Algorithm SHA256).Hash
    $uVer = (Get-Item $uiExe).VersionInfo.FileVersion
    if ($uVer -eq "2.2.8.0") {
        Write-Host "UI Exe:      $uVer | SHA256: $uHash [VERIFIED: v2.2.8.0 INSTALLED]" -ForegroundColor Green
    } else {
        Write-Host "UI Exe:      $uVer | SHA256: $uHash [WARNING: OLD VERSION DETECTED! Expected 2.2.8.0]" -ForegroundColor Red
    }
} else {
    Write-Host "UI Exe:      NOT FOUND" -ForegroundColor Red
}
Write-Host "================================================================" -ForegroundColor Cyan
