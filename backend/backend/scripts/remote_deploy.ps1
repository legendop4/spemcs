param(
    [Parameter(Mandatory=$true)][string]$TargetIP,
    [Parameter(Mandatory=$true)][string]$Username,
    [Parameter(Mandatory=$true)][string]$Password,
    [Parameter(Mandatory=$true)][string]$AgentSourcePath,
    [Parameter(Mandatory=$false)][string]$BackendApiUrl
)

$SecurePassword = ConvertTo-SecureString $Password -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential ($Username, $SecurePassword)

$TargetShare = "\\$TargetIP\c$\SpemcsAgent"

try {
    net use "\\$TargetIP\c$" $Password /user:$Username /y > $null
    
    if (Test-Path $TargetShare) {
        Remove-Item -Path $TargetShare -Recurse -Force -ErrorAction SilentlyContinue
    }
    New-Item -ItemType Directory -Path $TargetShare -Force > $null
    
    Copy-Item -Path "$AgentSourcePath\*" -Destination $TargetShare -Recurse -Force
} catch {
    Write-Error "Failed to copy files: $_"
    net use "\\$TargetIP\c$" /delete /y > $null
    exit 1
}

try {
    if ($BackendApiUrl) {
        $ConfigPath = "$TargetShare\service\appsettings.json"
        if (Test-Path $ConfigPath) {
            $Config = Get-Content $ConfigPath | ConvertFrom-Json
            $Config.BackendApiUrl = $BackendApiUrl
            $Config | ConvertTo-Json -Depth 10 | Set-Content $ConfigPath
        }
    }
} catch {
    Write-Warning "Could not update appsettings.json: $_"
}

net use "\\$TargetIP\c$" /delete /y > $null

try {
    Invoke-Command -ComputerName $TargetIP -Credential $Cred -ScriptBlock {
        cd C:\SpemcsAgent
        if (Get-Service SpemcsAgent -ErrorAction SilentlyContinue) {
            Stop-Service SpemcsAgent -ErrorAction SilentlyContinue
        }
        .\deployment\Install-SpemcsAgent.ps1 -ServiceExecutable ".\service\Spemcs.Agent.Service.exe"
        [System.Environment]::SetEnvironmentVariable("SPEMCS_AGENT_UI_PATH", "C:\SpemcsAgent\ui\Spemcs.Agent.UI.exe", "Machine")
        Start-Service SpemcsAgent
    }
    Write-Host "Deployment successful."
} catch {
    Write-Error "Failed to install service: $_"
    exit 1
}
