# Reads the built MSI's tables so installer claims can be checked against the package
# rather than against the .wxs source. Read-only: opens the database with mode 0 and never
# installs, repairs or touches the live system.
param(
    [string]$MsiPath = (Join-Path $PSScriptRoot 'dist\Spemcs.Agent.Setup.msi')
)

$ErrorActionPreference = 'Stop'

$installer = New-Object -ComObject WindowsInstaller.Installer
$db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($MsiPath, 0))

function Invoke-MsiQuery {
    param([string]$Sql, [int]$Columns)
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($Sql))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null)
    $rows = 0
    while ($true) {
        $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -eq $rec) { break }
        $rows++
        $fields = @()
        for ($i = 1; $i -le $Columns; $i++) {
            $fields += $rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, @($i))
        }
        Write-Output ('  ' + ($fields -join ' | '))
    }
    Write-Output "  [rows: $rows]"
}

Write-Output '=== ServiceInstall (Name | Display | StartType | Type | ErrorControl | Account) ==='
Invoke-MsiQuery 'SELECT `Name`,`DisplayName`,`StartType`,`ServiceType`,`ErrorControl`,`StartName` FROM `ServiceInstall`' 6

Write-Output '=== ServiceControl (Name | Event | Wait) ==='
Invoke-MsiQuery 'SELECT `Name`,`Event`,`Wait` FROM `ServiceControl`' 3

Write-Output '=== Wix4ServiceConfig (failure actions) ==='
Invoke-MsiQuery 'SELECT `ServiceName`,`FirstFailureActionType`,`SecondFailureActionType`,`ThirdFailureActionType`,`ResetPeriodInDays` FROM `Wix4ServiceConfig`' 5

Write-Output '=== Registry ==='
Invoke-MsiQuery 'SELECT `Root`,`Key`,`Name`,`Value` FROM `Registry`' 4

Write-Output '=== CreateFolder ==='
Invoke-MsiQuery 'SELECT `Directory_`,`Component_` FROM `CreateFolder`' 2

Write-Output '=== Directory (ProgramData / config targets) ==='
Invoke-MsiQuery 'SELECT `Directory`,`Directory_Parent`,`DefaultDir` FROM `Directory`' 3

Write-Output '=== CustomAction ==='
Invoke-MsiQuery 'SELECT `Action`,`Type`,`Source`,`Target` FROM `CustomAction`' 4

Write-Output '=== InstallExecuteSequence: launch + service actions ==='
Invoke-MsiQuery 'SELECT `Action`,`Condition`,`Sequence` FROM `InstallExecuteSequence`' 3

Write-Output '=== Property (selected) ==='
Invoke-MsiQuery 'SELECT `Property`,`Value` FROM `Property`' 2

Write-Output '=== Shortcut ==='
Invoke-MsiQuery 'SELECT `Shortcut`,`Directory_`,`Name`,`Target` FROM `Shortcut`' 4

Write-Output '=== Firewall-related tables (must be none) ==='
Invoke-MsiQuery 'SELECT `Name` FROM `_Tables`' 1

Write-Output '=== File Table Payload Verification ==='
$fileView = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @('SELECT `File`,`FileName`,`FileSize` FROM `File`'))
$fileView.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $fileView, $null)
$files = @()
while ($true) {
    $rec = $fileView.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $fileView, $null)
    if ($null -eq $rec) { break }
    $fn = $rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, @(2))
    if ($fn -match '\|') { $fn = ($fn -split '\|')[1] }
    $files += $fn
}

Write-Output "  Total files packaged in MSI: $($files.Count)"
$requiredFiles = @(
    'Spemcs.Agent.Service.exe',
    'Spemcs.Agent.UI.exe',
    'Spemcs.Agent.Service.dll',
    'Spemcs.Agent.UI.dll',
    'Spemcs.Agent.Core.dll',
    'Spemcs.Agent.Ipc.dll',
    'System.ServiceProcess.ServiceController.dll',
    'System.Diagnostics.EventLog.dll',
    'System.Diagnostics.EventLog.Messages.dll',
    'e_sqlite3.dll',
    'config.template.json'
)
foreach ($req in $requiredFiles) {
    $matchCount = ($files | Where-Object { $_ -eq $req }).Count
    if ($matchCount -gt 0) {
        Write-Output "  [OK] $req (count: $matchCount)"
    } else {
        throw "CRITICAL DEFECT: Required runtime file '$req' is MISSING from the MSI payload!"
    }
}
Write-Output "=== Payload Verification Succeeded ==="
