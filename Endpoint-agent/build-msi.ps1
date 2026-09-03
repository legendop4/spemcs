# SPEMCS Endpoint Agent - MSI Build Script
param(
    [string]$Configuration = "Release",
    [string]$Runtime = "win-x64"
)

$ErrorActionPreference = "Stop"

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$ProjectDir = Join-Path $ScriptDir "src\Spemcs.Agent.UI"
$InstallerDir = Join-Path $ScriptDir "installer"
$DistDir = Join-Path $InstallerDir "dist"
$PublishDir = Join-Path $ProjectDir "bin\$Configuration\net8.0-windows\$Runtime\publish"
$MsiOutput = Join-Path $DistDir "Spemcs.Agent.Setup.msi"

Write-Host "========================================================" -ForegroundColor Cyan
Write-Host " SPEMCS Endpoint Agent - MSI Installer Builder " -ForegroundColor Cyan
Write-Host "========================================================" -ForegroundColor Cyan

# 1. Check WiX CLI tool
Write-Host "`n[1/5] Checking WiX toolset..." -ForegroundColor Yellow
$wixVersion = wix --version
Write-Host "WiX Toolset version: $wixVersion" -ForegroundColor Green

# 2. Clean previous build and dist artifacts
Write-Host "`n[2/5] Cleaning output directories..." -ForegroundColor Yellow
if (Test-Path $DistDir) {
    Remove-Item -Path $DistDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Path $DistDir -Force | Out-Null

if (Test-Path $PublishDir) {
    Remove-Item -Path $PublishDir -Recurse -Force -ErrorAction SilentlyContinue
}

# 3. Restore and Build Solution
Write-Host "`n[3/5] Restoring and building solution..." -ForegroundColor Yellow
dotnet restore "$ScriptDir\Spemcs.Agent.sln"
if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed" }

# 4. Publish Self-Contained Agent
Write-Host "`n[4/5] Publishing self-contained win-x64 binary..." -ForegroundColor Yellow
dotnet publish "$ProjectDir\Spemcs.Agent.UI.csproj" -c $Configuration -r $Runtime --self-contained true -p:PublishSingleFile=false -p:TreatWarningsAsErrors=false

if ($LASTEXITCODE -ne 0) { throw "dotnet publish failed" }

if (-not (Test-Path "$PublishDir\Spemcs.Agent.UI.exe")) {
    throw "Published executable not found at $PublishDir\Spemcs.Agent.UI.exe"
}
Write-Host "Successfully published to: $PublishDir" -ForegroundColor Green

# 5. Build WiX MSI Package
Write-Host "`n[5/5] Building MSI Package with WiX..." -ForegroundColor Yellow
Push-Location $InstallerDir
try {
    wix build "Package.wxs" -arch x64 -o $MsiOutput
    if ($LASTEXITCODE -ne 0) { throw "WiX build failed" }
}
finally {
    Pop-Location
}

if (Test-Path $MsiOutput) {
    $fileInfo = Get-Item $MsiOutput
    $fileSizeMb = [math]::Round($fileInfo.Length / 1MB, 2)
    Write-Host "`n========================================================" -ForegroundColor Green
    Write-Host " [SUCCESS] MSI Installer built successfully!" -ForegroundColor Green
    Write-Host " Output: $MsiOutput" -ForegroundColor White
    Write-Host " Size:   $fileSizeMb MB" -ForegroundColor White
    Write-Host " Note:   Unsigned development package (No code-signing cert applied)" -ForegroundColor Gray
    Write-Host "========================================================" -ForegroundColor Green
} else {
    throw "MSI package was not created at target path."
}
