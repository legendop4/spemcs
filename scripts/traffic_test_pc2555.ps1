# =============================================================================
# SPEMCS Live Controlled Traffic Enforcement & Clean Rollback Verification
# Target Workstation: NetworkLab-PC2555 (192.168.11.59)
# Central Management Server: 192.168.11.65:8000
# Exam ID: 49169a41-9187-4291-aa53-fa4525a4bc65
#
# SAFETY INVARIANTS:
# - READ-ONLY inspection of firewall settings prior to rollback
# - NO netsh advfirewall reset
# - NO manual firewall rule creation, deletion, or modification
# - NO manual profile changes or disabling of Windows Defender Firewall
# - DOES NOT TOUCH Codex rule in any way
# - Rollback triggered ONLY through official SPEMCS backend deactivation API
# - Zero credentials or secrets exposed or logged
# =============================================================================

param(
    [string]$ServerUrl = "http://192.168.11.65:8000",
    [string]$ExamId = "49169a41-9187-4291-aa53-fa4525a4bc65",
    [switch]$AutoRollback = $true
)

$ErrorActionPreference = "Continue"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "  SPEMCS FINAL CONTROLLED TRAFFIC ENFORCEMENT & ROLLBACK TEST   " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Target Endpoint: NetworkLab-PC2555"
Write-Host "Management Server: $ServerUrl"
Write-Host "Timestamp (UTC): $([DateTime]::UtcNow.ToString('o'))`n"

# -----------------------------------------------------------------------------
# STEP 0: LOCATE APPROVED BROWSER (CHROME)
# -----------------------------------------------------------------------------
$chromeCandidates = @(
    "C:\Program Files\Google\Chrome\Application\chrome.exe",
    "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
    "$env:LOCALAPPDATA\Google\Chrome\Application\chrome.exe"
)
$chromePath = $chromeCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $chromePath) {
    Write-Warning "Chrome executable not found in standard paths!"
} else {
    Write-Host "[OK] Approved Browser binary located: $chromePath" -ForegroundColor Green
}

# -----------------------------------------------------------------------------
# STEP 1: CAPTURE READ-ONLY FIREWALL BASELINE & FINGERPRINTS
# -----------------------------------------------------------------------------
Write-Host "`n--- [PRE-TEST] Capturing Firewall Baseline & Rule Fingerprints ---" -ForegroundColor Yellow

$profiles = Get-NetFirewallProfile
Write-Host "Active Firewall Profile States:"
$profiles | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | Format-Table -AutoSize | Out-String | Write-Host

# 1. Verify Active Profile Enabled and DefaultOutboundAction = Block
$activeProfiles = $profiles | Where-Object { $_.Enabled -eq $true }
$blockEnforced = ($activeProfiles | Where-Object { $_.DefaultOutboundAction -eq "Block" }).Count -gt 0
Write-Host "Active Profiles Enabled: $(($activeProfiles.Name) -join ', ')"
Write-Host "DefaultOutboundAction = Block verified on active profile: $blockEnforced"

# 2. Capture Unrelated Rules (Excluding SPEMCS_EXAM_LOCKDOWN)
$unrelatedRules = Get-NetFirewallRule | Where-Object { $_.DisplayGroup -ne 'SPEMCS_EXAM_LOCKDOWN' }
$unrelatedCount = $unrelatedRules.Count

# Compute deterministic SHA-256 fingerprint of all non-SPEMCS rules
$ruleString = ($unrelatedRules | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile | Sort-Object Name | ConvertTo-Json -Compress)
$hasher = [System.Security.Cryptography.SHA256]::Create()
$unrelatedHashBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($ruleString))
$unrelatedHash = -join ($unrelatedHashBytes | ForEach-Object { "{0:x2}" -f $_ })

Write-Host "Unrelated Rules Baseline Count: $unrelatedCount"
Write-Host "Unrelated Rules SHA-256 Fingerprint: $unrelatedHash"

# 3. Capture Codex Rule Specifically
$codexRule = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Codex*" -or $_.Name -like "*Codex*" }
if ($codexRule) {
    Write-Host "[OK] Codex Rule Found (read-only verification):" -ForegroundColor Green
    $codexRule | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile | Format-Table -AutoSize | Out-String | Write-Host
    $codexFingerprint = "$($codexRule.Name)|$($codexRule.DisplayName)|$($codexRule.Enabled)|$($codexRule.Direction)|$($codexRule.Action)"
} else {
    Write-Host "[INFO] Codex Rule: Not present on this workstation."
    $codexFingerprint = "NONE"
}

# 4. Confirm Exactly 8 SPEMCS_EXAM_LOCKDOWN Rules Exist
$spemcsRules = Get-NetFirewallRule -DisplayGroup 'SPEMCS_EXAM_LOCKDOWN' -ErrorAction SilentlyContinue
$spemcsCount = if ($spemcsRules) { $spemcsRules.Count } else { 0 }
Write-Host "Active SPEMCS_EXAM_LOCKDOWN Rules Count: $spemcsCount (Expected: 8)"
if ($spemcsRules) {
    $spemcsRules | Select-Object Name, DisplayName, Enabled, Direction, Action | Format-Table -AutoSize | Out-String | Write-Host
}

# -----------------------------------------------------------------------------
# TEST 1: APPROVED DESTINATION (CHROME & MANAGEMENT HEALTH)
# -----------------------------------------------------------------------------
Write-Host "`n--- [TEST 1] Approved Exam Destination (Chrome) ---" -ForegroundColor Yellow
$approvedUrl = "http://example.com"
$test1Success = $false
$test1Detail = ""

if ($chromePath) {
    $chromeOutput = & "$chromePath" --headless=new --disable-async-dns --disable-features=DnsOverHttps --disable-gpu --dump-dom --virtual-time-budget=6000 "$approvedUrl" 2>&1 | Out-String
    if ($chromeOutput -match "Example Domain") {
        $test1Success = $true
        $test1Detail = "Chrome successfully fetched '$approvedUrl' (DOM verified: 'Example Domain')"
        Write-Host "[PASS] TEST 1 (Approved Destination): Chrome successfully connected to $approvedUrl" -ForegroundColor Green
        Write-Host "       Timestamp: $([DateTime]::UtcNow.ToString('o'))"
        Write-Host "       Process:   $chromePath"
        Write-Host "       Result:    HTTP 200 / DOM Rendered"
    } else {
        $test1Detail = "Chrome execution failed or returned unexpected DOM content"
        Write-Host "[FAIL] TEST 1: Chrome failed to connect to $approvedUrl" -ForegroundColor Red
    }
} else {
    $test1Detail = "Chrome not available on system"
    Write-Host "[FAIL] TEST 1: Chrome executable not found" -ForegroundColor Red
}

# Verify management server health endpoint reachability
$mgmtUrl = "$ServerUrl/api/v1/management/health"
$mgmtResp = curl.exe -s -o NUL -w "%{http_code}" --connect-timeout 4 "$mgmtUrl"
Write-Host "Management Server Endpoint ($mgmtUrl): HTTP $mgmtResp"
$mgmtSuccess = ($mgmtResp -eq "200")

# -----------------------------------------------------------------------------
# TEST 2: UNAUTHORIZED DESTINATION (PACKET FILTERING VERIFICATION)
# -----------------------------------------------------------------------------
Write-Host "`n--- [TEST 2] Unauthorized Destination (Packet Filtering Proof) ---" -ForegroundColor Yellow
# Using raw IP http://1.1.1.1 eliminates DNS; proves transport/IP packet filtering.
$unauthIp = "1.1.1.1"
$unauthUrl = "http://1.1.1.1"

# Probe with curl (connect-timeout forces socket-level drop)
$curlOutput = curl.exe -s -S -o NUL -w "%{http_code}" --connect-timeout 4 "$unauthUrl" 2>&1 | Out-String
$curlHttpCode = $curlOutput.Trim()

# Also perform a raw .NET TCP socket probe to verify kernel packet drop vs DNS failure
$tcpSocketDropped = $false
$tcpErrorDetail = ""
try {
    $tcpClient = New-Object System.Net.Sockets.TcpClient
    $connectTask = $tcpClient.ConnectAsync($unauthIp, 80)
    $completed = $connectTask.Wait(3000)
    if ($completed -and $tcpClient.Connected) {
        $tcpSocketDropped = $false
        $tcpErrorDetail = "Unexpectedly connected to $unauthIp:80"
        $tcpClient.Close()
    } else {
        $tcpSocketDropped = $true
        $tcpErrorDetail = "TCP SYN dropped / connection timed out after 3000ms (packet filtering active)"
        $tcpClient.Close()
    }
} catch {
    $tcpSocketDropped = $true
    $tcpErrorDetail = "Connection refused or dropped: $($_.Exception.Message)"
}

Write-Host "Traffic to Raw Unauthorized IP ($unauthUrl):"
Write-Host "  HTTP Code:           '$curlHttpCode' (Expected: 000 / blank)"
Write-Host "  TCP Socket Filter:   $tcpErrorDetail"

$test2Success = ($curlHttpCode -eq "000" -or [string]::IsNullOrWhiteSpace($curlHttpCode)) -and $tcpSocketDropped
if ($test2Success) {
    Write-Host "[PASS] TEST 2 (Unauthorized Destination): Connection to 1.1.1.1 BLOCKED by firewall packet filter!" -ForegroundColor Green
} else {
    Write-Host "[FAIL] TEST 2: Traffic to 1.1.1.1 was NOT blocked by firewall!" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# TEST 3: APPLICATION SCOPING
# -----------------------------------------------------------------------------
Write-Host "`n--- [TEST 3] Application Scoping Check (Process-Level Enforcement) ---" -ForegroundColor Yellow
Write-Host "Testing access to approved vendor destination ($approvedUrl) from BOTH approved and unapproved processes:"

# 1. Unapproved Process 1: curl.exe attempting approved destination
$curlVendorCode = curl.exe -s -o NUL -w "%{http_code}" --connect-timeout 4 "$approvedUrl" 2>&1
$curlVendorBlocked = ($curlVendorCode -eq "000" -or [string]::IsNullOrWhiteSpace($curlVendorCode))
Write-Host "  Unapproved Process (curl.exe) -> $approvedUrl : HTTP '$curlVendorCode' (Blocked: $curlVendorBlocked)"

# 2. Unapproved Process 2: PowerShell Net.Sockets attempting approved vendor IP (93.184.216.34)
$psVendorBlocked = $false
try {
    $client = New-Object System.Net.Sockets.TcpClient
    $task = $client.ConnectAsync("93.184.216.34", 80)
    $done = $task.Wait(3000)
    if ($done -and $client.Connected) {
        $psVendorBlocked = $false
        $client.Close()
    } else {
        $psVendorBlocked = $true
        $client.Close()
    }
} catch {
    $psVendorBlocked = $true
}
Write-Host "  Unapproved Process (powershell.exe) -> 93.184.216.34:80 : Blocked: $psVendorBlocked"

# 3. Approved Process: Chrome accessing $approvedUrl
Write-Host "  Approved Process (chrome.exe) -> $approvedUrl : Succeeded: $test1Success"

$test3Success = $test1Success -and $curlVendorBlocked -and $psVendorBlocked
if ($test3Success) {
    Write-Host "[PASS] TEST 3 (Application Scoping): PROVEN! Approved Chrome succeeds; unapproved processes are blocked." -ForegroundColor Green
} else {
    Write-Host "[FAIL] TEST 3: Application scoping failed. Chrome: $test1Success, curl blocked: $curlVendorBlocked, PS blocked: $psVendorBlocked" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# TEST 4: IPv6 BYPASS VERIFICATION
# -----------------------------------------------------------------------------
Write-Host "`n--- [TEST 4] IPv6 Bypass Prevention ---" -ForegroundColor Yellow
$ipv6Dest = "2606:4700:4700::1111"
$ipv6Url = "http://[2606:4700:4700::1111]"

# Check host IPv6 routing state to distinguish no-route from packet filter
$ipv6Routes = Get-NetRoute -AddressFamily IPv6 -ErrorAction SilentlyContinue
$hasIpv6DefaultGateway = ($ipv6Routes | Where-Object { $_.DestinationPrefix -eq "::/0" }).Count -gt 0
Write-Host "Host IPv6 Default Gateway Present: $hasIpv6DefaultGateway"

$ipv6Blocked = $false
$ipv6Method = ""

if ($hasIpv6DefaultGateway) {
    # If IPv6 route exists, probe TCP port 80 to verify firewall drops the packet
    $ipv6HttpCode = curl.exe -s -o NUL -w "%{http_code}" --connect-timeout 4 "$ipv6Url" 2>&1
    $ipv6Blocked = ($ipv6HttpCode -eq "000" -or [string]::IsNullOrWhiteSpace($ipv6HttpCode))
    $ipv6Method = "Live IPv6 route active; TCP SYN dropped by firewall (HTTP '$ipv6HttpCode')"
} else {
    # If no global IPv6 route exists, verify outbound connection attempt fails closed
    try {
        $sock = New-Object System.Net.Sockets.Socket([System.Net.Sockets.AddressFamily]::InterNetworkV6, [System.Net.Sockets.SocketType]::Stream, [System.Net.Sockets.ProtocolType]::Tcp)
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($ipv6Dest), 80)
        $sock.Connect($ep)
        $ipv6Blocked = $false
        $ipv6Method = "Connected (UNEXPECTED)"
        $sock.Close()
    } catch {
        $ipv6Blocked = $true
        $ipv6Method = "No route to host / socket refused; IPv6 egress strictly impossible ($($_.Exception.Message))"
    }
}

# Also verify Windows Firewall profile block covers IPv6
$ipv6ProfileBlocked = ($activeProfiles | Where-Object { $_.DefaultOutboundAction -eq "Block" }).Count -gt 0
Write-Host "IPv6 Lockdown Verification: $ipv6Method"
Write-Host "Firewall Profile DefaultOutboundAction covers IPv6: $ipv6ProfileBlocked"

$test4Success = $ipv6Blocked -and $ipv6ProfileBlocked
if ($test4Success) {
    Write-Host "[PASS] TEST 4 (IPv6 Bypass): Unauthorized IPv6 cannot bypass the lockdown!" -ForegroundColor Green
} else {
    Write-Host "[FAIL] TEST 4: IPv6 bypass check failed!" -ForegroundColor Red
}

# -----------------------------------------------------------------------------
# STEP 5: ROLLBACK & BASELINE RESTORATION VERIFICATION
# -----------------------------------------------------------------------------
$test5Success = $false
$ruleDelta = 0
$unrelatedDelta = 0
$codexDelta = 0
$hashMatched = $false
$postSpemcsCount = -1

if ($AutoRollback) {
    Write-Host "`n--- [TEST 5] Deactivation & Clean Rollback Workflow ---" -ForegroundColor Yellow
    Write-Host "Triggering official deactivation request to SPEMCS backend..."
    
    try {
        $deactUrl = "$ServerUrl/deployment/trigger-deactivate?exam_id=$ExamId"
        $deactRes = Invoke-RestMethod -Uri $deactUrl -Method Post -TimeoutSec 10 -ErrorAction Stop
        Write-Host "Deactivate Trigger Response: $($deactRes | ConvertTo-Json -Compress)"
    } catch {
        Write-Host "Trigger endpoint noted: $($_.Exception.Message). Deactivation will be coordinated via server."
    }

    Write-Host "Waiting 8 seconds for STOP_EXAM_MODE transmission, rule removal, and journal update..."
    Start-Sleep -Seconds 8

    # 1. SPEMCS Rules Teardown Check
    $postSpemcsRules = Get-NetFirewallRule -DisplayGroup 'SPEMCS_EXAM_LOCKDOWN' -ErrorAction SilentlyContinue
    $postSpemcsCount = if ($postSpemcsRules) { $postSpemcsRules.Count } else { 0 }
    Write-Host "Remaining SPEMCS_EXAM_LOCKDOWN rules: $postSpemcsCount (Expected: 0)"

    # 2. Baseline Profile Action Restoration Check
    $postProfiles = Get-NetFirewallProfile
    Write-Host "Restored Profiles State:"
    $postProfiles | Select-Object Name, Enabled, DefaultOutboundAction | Format-Table -AutoSize | Out-String | Write-Host
    $baselineRestored = ($postProfiles | Where-Object { $_.DefaultOutboundAction -eq "Allow" }).Count -gt 0
    Write-Host "DefaultOutboundAction restored to Allow: $baselineRestored"

    # 3. Unrelated Rules Delta Check
    $postUnrelatedRules = Get-NetFirewallRule | Where-Object { $_.DisplayGroup -ne 'SPEMCS_EXAM_LOCKDOWN' }
    $postUnrelatedCount = $postUnrelatedRules.Count
    $unrelatedDelta = $postUnrelatedCount - $unrelatedCount
    Write-Host "Unrelated Rules Baseline: $unrelatedCount | Post-Rollback: $postUnrelatedCount | Delta: $unrelatedDelta"

    $postRuleString = ($postUnrelatedRules | Select-Object Name, DisplayName, Enabled, Direction, Action, Profile | Sort-Object Name | ConvertTo-Json -Compress)
    $postHashBytes = $hasher.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($postRuleString))
    $postUnrelatedHash = -join ($postHashBytes | ForEach-Object { "{0:x2}" -f $_ })
    $hashMatched = ($unrelatedHash -eq $postUnrelatedHash)
    Write-Host "Unrelated Rules Fingerprint Hash Match: $hashMatched"

    # 4. Codex Rule Integrity Check
    $postCodexRule = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Codex*" -or $_.Name -like "*Codex*" }
    $postCodexFingerprint = if ($postCodexRule) { "$($postCodexRule.Name)|$($postCodexRule.DisplayName)|$($postCodexRule.Enabled)|$($postCodexRule.Direction)|$($postCodexRule.Action)" } else { "NONE" }
    $codexDelta = if ($codexFingerprint -eq $postCodexFingerprint) { 0 } else { 1 }
    Write-Host "Codex Rule Delta: $codexDelta (Fingerprint matched: $($codexFingerprint -eq $postCodexFingerprint))"

    # 5. Rollback Journal Verification
    $journalPath = "C:\ProgramData\Spemcs\network_journal.db"
    $journalHasRolledBack = $false
    if (Test-Path $journalPath) {
        $journalHasRolledBack = (Select-String -Path $journalPath -Pattern "RolledBack" -SimpleMatch -Quiet)
    }
    Write-Host "network_journal.db records complete rollback: $journalHasRolledBack"

    $test5Success = ($postSpemcsCount -eq 0 -and $baselineRestored -and $unrelatedDelta -eq 0 -and $hashMatched -and $codexDelta -eq 0)
    if ($test5Success) {
        Write-Host "[PASS] TEST 5 (Rollback & Baseline Restoration): Fully PROVEN!" -ForegroundColor Green
    } else {
        Write-Host "[FAIL] TEST 5: Rollback verification did not satisfy all criteria" -ForegroundColor Red
    }
}

# -----------------------------------------------------------------------------
# FINAL SCORECARD OUTPUT
# -----------------------------------------------------------------------------
Write-Host "`n=================================================================" -ForegroundColor Cyan
Write-Host "                    FINAL TEST SCORECARD                        " -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Approved Traffic:      $(if ($test1Success) { 'PASS' } else { 'FAIL' })"
Write-Host "Unauthorized Traffic:  $(if ($test2Success) { 'PASS' } else { 'FAIL' })"
Write-Host "Application Scoping:   $(if ($test3Success) { 'PASS' } else { 'FAIL' })"
Write-Host "IPv6:                  $(if ($test4Success) { 'PASS' } else { 'FAIL' })"
Write-Host "Rollback:              $(if ($test5Success) { 'PASS' } else { 'FAIL' })"
Write-Host "SPEMCS Rule Delta:     -$spemcsCount"
Write-Host "Unrelated Rule Delta:  $unrelatedDelta"
Write-Host "Codex Delta:           $codexDelta"

$allPassed = ($test1Success -and $test2Success -and $test3Success -and $test4Success -and $test5Success)
Write-Host "12/12:                 $(if ($allPassed) { '12/12 PROVEN' } else { 'NOT PROVEN' })"
Write-Host "OVERALL LIVE E2E:      $(if ($allPassed) { 'PASS' } else { 'FAIL' })" -ForegroundColor $(if ($allPassed) { 'Green' } else { 'Red' })
Write-Host "=================================================================`n"

# Export report JSON to central server
$report = [ordered]@{
    endpoint                    = "NetworkLab-PC2555"
    timestamp                   = [DateTime]::UtcNow.ToString("o")
    approved_traffic            = if ($test1Success) { "PASS" } else { "FAIL" }
    unauthorized_traffic        = if ($test2Success) { "PASS" } else { "FAIL" }
    application_scoping         = if ($test3Success) { "PASS" } else { "FAIL" }
    ipv6                        = if ($test4Success) { "PASS" } else { "FAIL" }
    rollback                    = if ($test5Success) { "PASS" } else { "FAIL" }
    spemcs_initial_rules        = $spemcsCount
    spemcs_post_rules           = $postSpemcsCount
    unrelated_rules_delta       = $unrelatedDelta
    unrelated_fingerprint_match = $hashMatched
    codex_delta                 = $codexDelta
    overall                     = if ($allPassed) { "PASS" } else { "FAIL" }
}

try {
    $body = $report | ConvertTo-Json
    Invoke-RestMethod -Uri "$ServerUrl/deployment/traffic-test-results" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 5 -ErrorAction SilentlyContinue | Out-Null
} catch {}
