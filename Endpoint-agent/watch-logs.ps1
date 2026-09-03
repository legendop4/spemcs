# SPEMCS Real-time Clean Log Monitor with Roll Number
$logFile = "C:\ProgramData\Spemcs\Logs\agent-$(Get-Date -Format 'yyyyMMdd').log"

if (-not (Test-Path $logFile)) {
    Write-Host "No log file found for today at $logFile" -ForegroundColor Yellow
    exit 0
}

Write-Host "===================================================================================" -ForegroundColor Cyan
Write-Host "                      SPEMCS REAL-TIME LOG & ROLL MONITOR                          " -ForegroundColor Cyan
Write-Host "===================================================================================" -ForegroundColor Cyan
Write-Host "Time     | Level       | Roll Number     | Event / Message" -ForegroundColor Gray
Write-Host "-----------------------------------------------------------------------------------" -ForegroundColor Gray

Get-Content $logFile -Tail 20 -Wait | ForEach-Object {
    try {
        $l = $_ | ConvertFrom-Json
        $time = [DateTime]::Parse($l.TimestampUtc).ToString("HH:mm:ss")
        $level = $l.Level
        $msg = $l.Message

        $roll = "N/A"
        if ($msg -match 'roll=([^\s]+)') {
            $roll = $matches[1]
        }

        $color = "White"
        if ($msg -like "*LIVE DETECTION*") { $color = "Green" }
        elseif ($level -eq "Warning") { $color = "Yellow" }
        elseif ($level -eq "Error" -or $level -eq "Critical") { $color = "Red" }
        elseif ($msg -like "*transition*") { $color = "Cyan" }

        Write-Host ("{0,-8} | {1,-11} | {2,-15} | {3}" -f $time, $level, $roll, $msg) -ForegroundColor $color
    } catch {
        # Skip incomplete log lines
    }
}
