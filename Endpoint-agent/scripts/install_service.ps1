$ErrorActionPreference = "Stop"
$svcName = "SPEMCS Endpoint Agent"
$binPath = "C:\Users\shrma\Desktop\spemcsnew\Endpoint-agent\src\Spemcs.Agent.Service\bin\Debug\net8.0-windows\Spemcs.Agent.Service.exe"

# Stop and delete if existing
try {
    & sc.exe stop $svcName | Out-Null
    $waitCount = 0
    while ((Get-Process -Name "Spemcs.Agent.Service" -ErrorAction SilentlyContinue) -and ($waitCount -lt 10)) {
        Start-Sleep -Seconds 1
        $waitCount++
    }
} catch { }

try {
    & sc.exe delete $svcName | Out-Null
    Start-Sleep -Seconds 1
} catch { }

Write-Host "Building solution to ensure latest binaries..."
& dotnet build "C:\Users\shrma\Desktop\spemcsnew\Endpoint-agent\Spemcs.Agent.sln" -c Debug
if ($LASTEXITCODE -ne 0) { throw "Build failed with exit code $LASTEXITCODE" }

Write-Host "Creating service: $svcName with binPath: $binPath"
& sc.exe create $svcName binPath= "`"$binPath`"" start= auto obj= "NT AUTHORITY\SYSTEM" DisplayName= "SPEMCS Endpoint Agent"
& sc.exe failure $svcName reset= 86400 actions= restart/5000/restart/10000/restart/60000
Start-Sleep -Seconds 1
Write-Host "Starting service..."
& sc.exe start $svcName
Start-Sleep -Seconds 2
& sc.exe query $svcName
