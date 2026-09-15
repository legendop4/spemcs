# SPEMCS Endpoint Agent - Self-Contained MSI Build Script
param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ServiceProject = Join-Path $ScriptDir "src\Spemcs.Agent.Service\Spemcs.Agent.Service.csproj"
$UiProject = Join-Path $ScriptDir "src\Spemcs.Agent.UI\Spemcs.Agent.UI.csproj"
$InstallerDir = Join-Path $ScriptDir "installer"
$WixProj = Join-Path $InstallerDir "Spemcs.Agent.Installer.wixproj"
$DistDir = Join-Path $InstallerDir "dist"
$StageDir = Join-Path $ScriptDir "publish\stage"
$MsiOutput = Join-Path $DistDir "Spemcs.Agent.Setup.msi"
$VerifyScript = Join-Path $InstallerDir "verify-msi.ps1"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " SPEMCS Endpoint Agent - Self-Contained MSI Builder " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Resolve working .NET SDK
Write-Host "`n[1/5] Checking .NET SDK environment..." -ForegroundColor Yellow
if (Test-Path "C:\Users\Server\dotnet\dotnet.exe") {
    $env:DOTNET_ROOT = "C:\Users\Server\dotnet"
    $env:Path = "C:\Users\Server\dotnet;$env:Path"
}
$dotnetVersion = dotnet --version
Write-Host ".NET SDK version: $dotnetVersion" -ForegroundColor Green

# 2. Clean previous build artifacts
Write-Host "`n[2/5] Preparing output and staging directories..." -ForegroundColor Yellow
if (-not (Test-Path $DistDir)) {
    New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
}
if (-not (Test-Path $StageDir)) {
    New-Item -ItemType Directory -Path $StageDir -Force | Out-Null
}

# 3. Restore Solution
Write-Host "`n[3/5] Restoring solution dependencies..." -ForegroundColor Yellow
dotnet restore "$ScriptDir\Spemcs.Agent.sln"
if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed" }

# 4. Publish Self-Contained Service and UI
Write-Host "`n[4/5] Publishing self-contained $Runtime binaries into staging..." -ForegroundColor Yellow

Write-Host "  -> Publishing Spemcs.Agent.Service..." -ForegroundColor Gray
dotnet publish $ServiceProject -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=false -p:TreatWarningsAsErrors=false -o $StageDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish Service failed" }

Write-Host "  -> Publishing Spemcs.Agent.UI..." -ForegroundColor Gray
dotnet publish $UiProject -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=false -p:TreatWarningsAsErrors=false -o $StageDir
if ($LASTEXITCODE -ne 0) { throw "dotnet publish UI failed" }

if (-not (Test-Path "$StageDir\Spemcs.Agent.Service.exe")) {
    throw "Published service executable not found at $StageDir\Spemcs.Agent.Service.exe"
}
if (-not (Test-Path "$StageDir\Spemcs.Agent.UI.exe")) {
    throw "Published UI executable not found at $StageDir\Spemcs.Agent.UI.exe"
}
if (-not (Test-Path "$StageDir\coreclr.dll")) {
    throw "Self-contained coreclr.dll missing from $StageDir"
}

$stageFileCount = (Get-ChildItem -Path $StageDir -Recurse -File).Count
Write-Host "Successfully published $stageFileCount self-contained files to: $StageDir" -ForegroundColor Green

# 5. Build WiX MSI Package
Write-Host "`n[5/5] Building WiX MSI Package..." -ForegroundColor Yellow
dotnet build $WixProj -c $Configuration
if ($LASTEXITCODE -ne 0) { throw "WiX MSI build failed" }

if (Test-Path $MsiOutput) {
    $fileInfo = Get-Item $MsiOutput
    $fileSizeMb = [math]::Round($fileInfo.Length / 1MB, 2)
    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host " [SUCCESS] MSI Installer built successfully!" -ForegroundColor Green
    Write-Host " Output: $MsiOutput" -ForegroundColor White
    Write-Host " Size:   $fileSizeMb MB (Self-Contained win-x64)" -ForegroundColor White
    Write-Host " Note:   Includes .NET 8 runtime - zero client prerequisites" -ForegroundColor Gray
    Write-Host "========================================================" -ForegroundColor Green

    # Run verify-msi.ps1
    if (Test-Path $VerifyScript) {
        Write-Host "`nRunning automated MSI payload verification..." -ForegroundColor Yellow
        & $VerifyScript -MsiPath $MsiOutput
    }
} else {
    throw "MSI package was not created at $MsiOutput."
}
