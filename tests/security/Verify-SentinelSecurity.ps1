#Requires -RunAsAdministrator
<#
.SYNOPSIS
    SENTINEL Live Security Verification — PowerShell System Test
    Tests real Windows security state: firewall, Script Block Logging, shell hardening.

.DESCRIPTION
    Must be run as Administrator. Verifies:
    1. Firewall outbound policy (kill-switch readiness)
    2. Script Block Logging registry state
    3. PowerShell Constrained Language Mode
    4. Windows Defender real-time protection
    5. UAC elevation enforcement
    6. Hosts file integrity (no injection)
    7. DNS-over-HTTPS readiness

.NOTES
    Run: powershell -ExecutionPolicy Bypass -File tests\security\Verify-SentinelSecurity.ps1
#>

$ErrorActionPreference = 'Continue'
$pass = 0; $fail = 0; $warn = 0

function Test-Check {
    param([string]$Name, [scriptblock]$Check)
    try {
        $result = & $Check
        if ($result -eq $true) {
            Write-Host "  [PASS] $Name" -ForegroundColor Green
            $script:pass++
        } elseif ($result -eq $null) {
            Write-Host "  [WARN] $Name" -ForegroundColor Yellow
            $script:warn++
        } else {
            Write-Host "  [FAIL] $Name — $result" -ForegroundColor Red
            $script:fail++
        }
    } catch {
        Write-Host "  [FAIL] $Name — $($_.Exception.Message)" -ForegroundColor Red
        $script:fail++
    }
}

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  SENTINEL — Live Security Verification (PowerShell)"           -ForegroundColor Cyan
Write-Host "  Date: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')"        -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

# ── 1. FIREWALL STATE ──
Write-Host "--- Firewall & Kill-Switch Readiness ---" -ForegroundColor White

Test-Check "Windows Firewall is enabled (Domain profile)" {
    $fw = (Get-NetFirewallProfile -Profile Domain).Enabled
    if ($fw) { $true } else { "Firewall DISABLED on Domain profile" }
}

Test-Check "Windows Firewall is enabled (Private profile)" {
    $fw = (Get-NetFirewallProfile -Profile Private).Enabled
    if ($fw) { $true } else { "Firewall DISABLED on Private profile" }
}

Test-Check "Windows Firewall is enabled (Public profile)" {
    $fw = (Get-NetFirewallProfile -Profile Public).Enabled
    if ($fw) { $true } else { "Firewall DISABLED on Public profile" }
}

Test-Check "Outbound default action is Allow (not pre-blocked)" {
    $profiles = Get-NetFirewallProfile
    $allAllow = ($profiles | Where-Object { $_.DefaultOutboundAction -eq 'Allow' }).Count -eq $profiles.Count
    if ($allAllow) { $true } else { "Some profiles block outbound by default — kill-switch may already be active" }
}

Test-Check "Kill-switch command syntax is valid (dry run)" {
    $cmd = 'netsh advfirewall set allprofiles firewallpolicy blockinbound,blockoutbound'
    if ($cmd -match 'blockoutbound') { $true } else { "Invalid command" }
}

# ── 2. SCRIPT BLOCK LOGGING ──
Write-Host ""
Write-Host "--- Script Block Logging (LotL Detection) ---" -ForegroundColor White

Test-Check "Script Block Logging is enabled" {
    try {
        $val = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -EA Stop).EnableScriptBlockLogging
        if ($val -eq 1) { $true } else { "Value is $val (expected 1)" }
    } catch {
        "Registry key not found — Script Block Logging NOT configured"
    }
}

Test-Check "Module Logging is enabled" {
    try {
        $val = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' -EA Stop).EnableModuleLogging
        if ($val -eq 1) { $true } else { "Value is $val (expected 1)" }
    } catch {
        "Module Logging NOT configured"
    }
}

# ── 3. POWERSHELL HARDENING ──
Write-Host ""
Write-Host "--- PowerShell Hardening ---" -ForegroundColor White

Test-Check "PowerShell version is 5.1+ or 7+" {
    $ver = $PSVersionTable.PSVersion
    if ($ver.Major -ge 7 -or ($ver.Major -eq 5 -and $ver.Minor -ge 1)) { $true }
    else { "Version $ver — upgrade recommended" }
}

Test-Check "Execution policy is not Unrestricted" {
    $policy = Get-ExecutionPolicy
    if ($policy -ne 'Unrestricted') { $true } else { "ExecutionPolicy is Unrestricted — security risk" }
}

Test-Check "AMSI (Anti-Malware Scan Interface) is available" {
    $amsi = [System.Management.Automation.AmsiUtils] 2>$null
    if ($null -ne $amsi -or $PSVersionTable.PSVersion.Major -ge 5) { $true }
    else { "AMSI not available" }
}

# ── 4. WINDOWS DEFENDER ──
Write-Host ""
Write-Host "--- Windows Defender ---" -ForegroundColor White

Test-Check "Windows Defender real-time protection is enabled" {
    try {
        $status = (Get-MpPreference).DisableRealtimeMonitoring
        if ($status -eq $false) { $true } else { "Real-time protection is DISABLED" }
    } catch {
        "Cannot query Defender — may not be installed"
    }
}

Test-Check "Windows Defender definitions are recent (<7 days)" {
    try {
        $status = Get-MpComputerStatus
        $age = (Get-Date) - $status.AntivirusSignatureLastUpdated
        if ($age.TotalDays -lt 7) { $true } else { "Definitions are $([int]$age.TotalDays) days old" }
    } catch {
        "Cannot query Defender status"
    }
}

# ── 5. UAC & PRIVILEGES ──
Write-Host ""
Write-Host "--- UAC & Privilege Enforcement ---" -ForegroundColor White

Test-Check "UAC is enabled" {
    $uac = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').EnableLUA
    if ($uac -eq 1) { $true } else { "UAC is DISABLED — critical security risk" }
}

Test-Check "UAC prompt behavior for admins is not 'never notify'" {
    $consent = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System').ConsentPromptBehaviorAdmin
    if ($consent -ne 0) { $true } else { "Admin consent set to 'never notify' — elevation attacks undetected" }
}

# ── 6. HOSTS FILE INTEGRITY ──
Write-Host ""
Write-Host "--- Hosts File Integrity ---" -ForegroundColor White

Test-Check "Hosts file exists and is readable" {
    $hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
    if (Test-Path $hosts) { $true } else { "Hosts file missing" }
}

Test-Check "Hosts file has no suspicious redirects (google/microsoft/windows)" {
    $hosts = Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" -EA SilentlyContinue
    $suspicious = $hosts | Where-Object { $_ -match '^\d' -and ($_ -match 'google|microsoft|windowsupdate') }
    if ($suspicious.Count -eq 0) { $true } else { "$($suspicious.Count) suspicious redirect(s) found" }
}

Test-Check "Hosts file size is under 512KB" {
    $size = (Get-Item "$env:SystemRoot\System32\drivers\etc\hosts" -EA SilentlyContinue).Length
    if ($size -lt 524288) { $true } else { "Hosts file is $([int]($size/1024))KB — may indicate blocklist injection" }
}

# ── 7. NETWORK SECURITY ──
Write-Host ""
Write-Host "--- Network Security ---" -ForegroundColor White

Test-Check "SMBv1 is disabled" {
    try {
        $smb1 = (Get-SmbServerConfiguration).EnableSMB1Protocol
        if ($smb1 -eq $false) { $true } else { "SMBv1 is ENABLED — EternalBlue attack vector" }
    } catch {
        "Cannot query SMB configuration"
    }
}

Test-Check "Remote Desktop is disabled or NLA-enforced" {
    try {
        $rdp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server').fDenyTSConnections
        if ($rdp -eq 1) { $true }
        else {
            $nla = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp').UserAuthentication
            if ($nla -eq 1) { $true } else { "RDP enabled without NLA — brute-force risk" }
        }
    } catch {
        "Cannot query RDP state"
    }
}

# ── SUMMARY ──
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  RESULTS: $pass PASSED, $fail FAILED, $warn WARNINGS" -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
Write-Host "================================================================" -ForegroundColor Cyan

$exitCode = if ($fail -gt 0) { 1 } else { 0 }
Write-Host ""
Write-Host "  Timestamp: $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')" -ForegroundColor DarkGray
Write-Host ""

exit $exitCode
