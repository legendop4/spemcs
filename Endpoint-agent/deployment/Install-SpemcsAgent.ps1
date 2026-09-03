param(
    [Parameter(Mandatory=$true)][string]$ServiceExecutable,
    [string]$ServiceName = "SpemcsAgent"
)
$resolved = (Resolve-Path -LiteralPath $ServiceExecutable).Path
if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) { throw "Service executable not found: $resolved" }
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) { throw "Service already exists: $ServiceName" }
New-Service -Name $ServiceName -BinaryPathName "`"$resolved`"" -DisplayName "SPEMCS Endpoint Agent" -StartupType Automatic
Write-Host "Installed $ServiceName. Start with: Start-Service $ServiceName"
