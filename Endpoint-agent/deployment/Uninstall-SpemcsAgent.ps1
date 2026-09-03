param([string]$ServiceName = "SpemcsAgent")
$service = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $service) { Write-Host "Service is not installed: $ServiceName"; exit 0 }
if ($service.Status -ne "Stopped") { Stop-Service -Name $ServiceName -Force }
sc.exe delete $ServiceName | Out-Host
