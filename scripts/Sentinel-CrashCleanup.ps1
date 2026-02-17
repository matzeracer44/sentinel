#Requires -Version 5.1
<#
.SYNOPSIS
    SENTINEL OSOP — Crash Cleanup Fallback (BSI APP.6.A13)
    Runs if Electron process crashes before performing graceful session wipe.

.DESCRIPTION
    Reads the PID file (.sentinel-session.pid) left by sessionManager.ts.
    If the PID is dead (crashed), performs the same wipe that would have
    happened in the Electron before-quit handler:
      - Deletes activity.log, scan-results.json, sbom-manifest.json
      - Deletes security_events.db + WAL/SHM
      - Deletes .sentinel/ telemetry LevelDB
      - Deletes threat-intel/ioc-cache.json
      - Deletes Electron Cache/GPUCache/Session Storage/Local Storage
      - Removes the PID file itself

    Preserves: auth-config.json, sentinelConfig.json, updates/, siem-exports/

.PARAMETER UserDataPath
    Override path to Sentinel userData. Auto-detected from PID file if omitted.

.PARAMETER Force
    Skip PID check and force cleanup even if Sentinel is still running.

.EXAMPLE
    .\Sentinel-CrashCleanup.ps1
    .\Sentinel-CrashCleanup.ps1 -Force
    .\Sentinel-CrashCleanup.ps1 -UserDataPath "$env:APPDATA\sentinel"

.NOTES
    Schedule via Task Scheduler at logon for automatic crash recovery.
    Run: schtasks /create /tn "Sentinel-CrashCleanup" /tr "powershell -ExecutionPolicy Bypass -File scripts\Sentinel-CrashCleanup.ps1" /sc onlogon /rl highest
#>

[CmdletBinding()]
param(
    [string]$UserDataPath,
    [switch]$Force
)

$ErrorActionPreference = 'Continue'

# ── Resolve userData path ──
function Resolve-UserData {
    if ($UserDataPath) { return $UserDataPath }

    # Standard Electron userData locations
    $candidates = @(
        "$env:APPDATA\sentinel",
        "$env:APPDATA\Sentinel",
        "$env:APPDATA\SENTINEL",
        "$env:LOCALAPPDATA\sentinel",
        "$env:LOCALAPPDATA\Sentinel"
    )

    foreach ($c in $candidates) {
        $pidFile = Join-Path $c '.sentinel-session.pid'
        if (Test-Path $pidFile) {
            try {
                $pidData = Get-Content $pidFile -Raw | ConvertFrom-Json
                if ($pidData.userData) { return $pidData.userData }
            } catch { }
            return $c
        }
        if (Test-Path $c) { return $c }
    }

    Write-Warning "[OSOP] Cannot locate Sentinel userData directory"
    return $null
}

# ── Check if Sentinel is still running ──
function Test-SentinelRunning {
    param([string]$DataPath)
    $pidFile = Join-Path $DataPath '.sentinel-session.pid'
    if (-not (Test-Path $pidFile)) { return $false }

    try {
        $pidData = Get-Content $pidFile -Raw | ConvertFrom-Json
        $proc = Get-Process -Id $pidData.pid -ErrorAction SilentlyContinue
        if ($proc -and -not $proc.HasExited) {
            return $true
        }
    } catch { }
    return $false
}

# ── Secure delete: overwrite with random bytes, then remove ──
function Remove-SecureFile {
    param([string]$FilePath)
    if (-not (Test-Path $FilePath)) { return }
    try {
        $size = (Get-Item $FilePath).Length
        if ($size -gt 0 -and $size -lt 104857600) { # <100MB
            $bytes = New-Object byte[] ([Math]::Min($size, 65536))
            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $rng.GetBytes($bytes)
            $stream = [System.IO.File]::OpenWrite($FilePath)
            $written = 0
            while ($written -lt $size) {
                $toWrite = [Math]::Min($bytes.Length, $size - $written)
                $stream.Write($bytes, 0, $toWrite)
                $written += $toWrite
            }
            $stream.Flush()
            $stream.Close()
            $rng.Dispose()
        }
        Remove-Item $FilePath -Force -ErrorAction Stop
        Write-Host "  [DEL] $FilePath" -ForegroundColor DarkGray
    } catch {
        try { Remove-Item $FilePath -Force -ErrorAction SilentlyContinue } catch { }
        Write-Warning "  [ERR] $FilePath : $($_.Exception.Message)"
    }
}

# ── Secure delete directory recursively ──
function Remove-SecureDirectory {
    param([string]$DirPath)
    if (-not (Test-Path $DirPath)) { return }
    try {
        Get-ChildItem $DirPath -Recurse -File | ForEach-Object {
            Remove-SecureFile $_.FullName
        }
        Remove-Item $DirPath -Recurse -Force -ErrorAction Stop
        Write-Host "  [DIR] $DirPath" -ForegroundColor DarkGray
    } catch {
        Write-Warning "  [ERR] $DirPath : $($_.Exception.Message)"
    }
}

# ══════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════

Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  SENTINEL OSOP — Crash Cleanup (BSI APP.6.A13)"               -ForegroundColor Cyan
Write-Host "  $(Get-Date -Format 'yyyy-MM-ddTHH:mm:ss.fffZ')"              -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

$dataPath = Resolve-UserData
if (-not $dataPath) {
    Write-Error "Cannot find Sentinel userData. Use -UserDataPath to specify."
    exit 1
}

Write-Host "  userData: $dataPath" -ForegroundColor White

if (-not $Force) {
    if (Test-SentinelRunning $dataPath) {
        Write-Host "  Sentinel is still running — no cleanup needed." -ForegroundColor Green
        Write-Host "  Use -Force to override." -ForegroundColor DarkGray
        exit 0
    }
    Write-Host "  Sentinel NOT running — performing crash cleanup..." -ForegroundColor Yellow
} else {
    Write-Host "  Force mode — cleaning regardless of process state..." -ForegroundColor Yellow
}

$deleted = 0
$errors = 0

# 1. Ephemeral files
Write-Host ""
Write-Host "--- Ephemeral Files ---" -ForegroundColor White
$ephemeralFiles = @('activity.log', 'scan-results.json', 'sbom-manifest.json')
foreach ($f in $ephemeralFiles) {
    $fp = Join-Path $dataPath $f
    if (Test-Path $fp) {
        Remove-SecureFile $fp
        $deleted++
    }
}

# 2. Security events DB (SQLite + WAL/SHM)
Write-Host ""
Write-Host "--- Security Events DB ---" -ForegroundColor White
$dbPatterns = @('security_events.db', 'security_events.db-wal', 'security_events.db-shm')
$dbDirs = @($dataPath, (Get-Location).Path)
foreach ($dir in $dbDirs) {
    foreach ($dbFile in $dbPatterns) {
        $fp = Join-Path $dir $dbFile
        if (Test-Path $fp) {
            Remove-SecureFile $fp
            $deleted++
        }
    }
}

# 3. Telemetry LevelDB
Write-Host ""
Write-Host "--- Telemetry Store ---" -ForegroundColor White
$telemetryDir = Join-Path (Get-Location).Path '.sentinel'
if (Test-Path $telemetryDir) {
    Remove-SecureDirectory $telemetryDir
    $deleted++
}

# 4. Threat Intel cache
Write-Host ""
Write-Host "--- Threat Intel Cache ---" -ForegroundColor White
$iocCache = Join-Path $dataPath 'threat-intel\ioc-cache.json'
if (Test-Path $iocCache) {
    Remove-SecureFile $iocCache
    $deleted++
}

# 5. ARGUS temp dirs
Write-Host ""
Write-Host "--- ARGUS Sandbox ---" -ForegroundColor White
foreach ($argDir in @('argus-temp', 'argus-cache')) {
    $fp = Join-Path $dataPath $argDir
    if (Test-Path $fp) {
        Remove-SecureDirectory $fp
        $deleted++
    }
}

# 6. Electron cache dirs
Write-Host ""
Write-Host "--- Electron Caches ---" -ForegroundColor White
$electronCacheDirs = @('Cache', 'GPUCache', 'Code Cache', 'DawnCache', 'Session Storage', 'Local Storage')
foreach ($cacheDir in $electronCacheDirs) {
    $fp = Join-Path $dataPath $cacheDir
    if (Test-Path $fp) {
        Remove-SecureDirectory $fp
        $deleted++
    }
}

# 7. Remove PID file
Write-Host ""
Write-Host "--- PID File ---" -ForegroundColor White
$pidFile = Join-Path $dataPath '.sentinel-session.pid'
if (Test-Path $pidFile) {
    Remove-Item $pidFile -Force -ErrorAction SilentlyContinue
    Write-Host "  [DEL] $pidFile" -ForegroundColor DarkGray
    $deleted++
}

# ── Summary ──
Write-Host ""
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "  Cleanup complete: $deleted items removed" -ForegroundColor $(if ($errors -eq 0) { 'Green' } else { 'Yellow' })
Write-Host "  Preserved: auth-config.json, sentinelConfig.json, updates/, siem-exports/" -ForegroundColor DarkGray
Write-Host "================================================================" -ForegroundColor Cyan
Write-Host ""

exit 0
