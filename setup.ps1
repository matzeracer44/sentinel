#Requires -Version 5.1
<#
.SYNOPSIS
    Sentinel Security Suite — Automatisches Setup-Skript
    Installiert alle Abhängigkeiten und baut Sentinel auf jedem Windows-System.

.DESCRIPTION
    Dieses Skript:
    1. Prüft Systemvoraussetzungen (Windows 10+, PowerShell 5.1+)
    2. Installiert Node.js (LTS) falls nicht vorhanden
    3. Installiert Python 3.x falls nicht vorhanden (für ARGUS Backend)
    4. Installiert npm-Abhängigkeiten
    5. Erstellt die .env-Datei aus .env.example
    6. Baut Sentinel (TypeScript + Webpack)
    7. Startet Sentinel

.NOTES
    Ausführen: PowerShell als Administrator öffnen, dann:
    Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
    .\setup.ps1
#>

param(
    [switch]$SkipNodeInstall,
    [switch]$SkipPythonInstall,
    [switch]$SkipBuild,
    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# ═══════════════════════════════════════════
# FARBEN & AUSGABE
# ═══════════════════════════════════════════

function Write-Step($msg) { Write-Host "`n[SENTINEL] $msg" -ForegroundColor Cyan }
function Write-Ok($msg)   { Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "  [!!] $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "  [FEHLER] $msg" -ForegroundColor Red }
function Write-Info($msg) { Write-Host "  $msg" -ForegroundColor Gray }

# ═══════════════════════════════════════════
# BANNER
# ═══════════════════════════════════════════

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║         SENTINEL SECURITY SUITE               ║" -ForegroundColor Cyan
Write-Host "  ║         Automatisches Setup v3.0               ║" -ForegroundColor Cyan
Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

# ═══════════════════════════════════════════
# 1. SYSTEMVORAUSSETZUNGEN
# ═══════════════════════════════════════════

Write-Step "Pruefe Systemvoraussetzungen..."

# Windows-Version
$osVersion = [System.Environment]::OSVersion.Version
if ($osVersion.Major -lt 10) {
    Write-Fail "Windows 10 oder neuer erforderlich (aktuell: $($osVersion.ToString()))"
    exit 1
}
Write-Ok "Windows $($osVersion.Major).$($osVersion.Minor) erkannt"

# PowerShell-Version
$psVer = $PSVersionTable.PSVersion
if ($psVer.Major -lt 5) {
    Write-Fail "PowerShell 5.1+ erforderlich (aktuell: $psVer)"
    exit 1
}
Write-Ok "PowerShell $psVer"

# Admin-Rechte prüfen
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {
    Write-Ok "Administrator-Rechte vorhanden"
} else {
    Write-Warn "Kein Administrator — einige Sentinel-Features benoetigen Admin-Rechte"
    Write-Info "Sentinel kann ohne Admin installiert werden, aber fuer volle Funktionalitaet:"
    Write-Info "  Rechtsklick auf PowerShell -> 'Als Administrator ausfuehren'"
}

# ═══════════════════════════════════════════
# 2. NODE.JS
# ═══════════════════════════════════════════

Write-Step "Pruefe Node.js..."

$nodeInstalled = $false
try {
    $nodeVersion = & node --version 2>$null
    if ($nodeVersion -match '^v(\d+)') {
        $nodeMajor = [int]$Matches[1]
        if ($nodeMajor -ge 18) {
            Write-Ok "Node.js $nodeVersion gefunden"
            $nodeInstalled = $true
        } else {
            Write-Warn "Node.js $nodeVersion ist zu alt (mindestens v18 erforderlich)"
        }
    }
} catch {
    Write-Info "Node.js nicht gefunden"
}

if (-not $nodeInstalled -and -not $SkipNodeInstall) {
    Write-Step "Installiere Node.js LTS..."
    
    # Versuche winget zuerst
    $wingetAvail = $false
    try {
        $null = & winget --version 2>$null
        $wingetAvail = $true
    } catch {}

    if ($wingetAvail) {
        Write-Info "Verwende winget..."
        & winget install OpenJS.NodeJS.LTS --accept-package-agreements --accept-source-agreements --silent 2>$null
        
        # PATH aktualisieren
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        
        try {
            $nodeVersion = & node --version 2>$null
            Write-Ok "Node.js $nodeVersion installiert via winget"
            $nodeInstalled = $true
        } catch {
            Write-Warn "winget-Installation fehlgeschlagen, versuche direkten Download..."
        }
    }
    
    if (-not $nodeInstalled) {
        # Direkter Download
        $nodeUrl = "https://nodejs.org/dist/v22.14.0/node-v22.14.0-x64.msi"
        $installerPath = Join-Path $env:TEMP "node-installer.msi"
        
        Write-Info "Lade Node.js LTS herunter..."
        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $nodeUrl -OutFile $installerPath -UseBasicParsing
            
            Write-Info "Installiere Node.js..."
            Start-Process msiexec.exe -ArgumentList "/i `"$installerPath`" /qn /norestart" -Wait -NoNewWindow
            
            # PATH aktualisieren
            $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
            
            $nodeVersion = & node --version 2>$null
            Write-Ok "Node.js $nodeVersion installiert"
            $nodeInstalled = $true
            
            Remove-Item $installerPath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Fail "Node.js konnte nicht installiert werden: $_"
            Write-Info "Bitte manuell installieren: https://nodejs.org/en/download/"
            exit 1
        }
    }
} elseif (-not $nodeInstalled) {
    Write-Fail "Node.js v18+ wird benoetigt. Installation uebersprungen (--SkipNodeInstall)"
    exit 1
}

# npm prüfen
try {
    $npmVersion = & npm --version 2>$null
    Write-Ok "npm $npmVersion"
} catch {
    Write-Fail "npm nicht gefunden. Bitte Node.js neu installieren."
    exit 1
}

# ═══════════════════════════════════════════
# 3. PYTHON (für ARGUS Backend)
# ═══════════════════════════════════════════

Write-Step "Pruefe Python (fuer ARGUS Backend)..."

$pythonInstalled = $false
try {
    $pyVersion = & python --version 2>$null
    if ($pyVersion -match 'Python 3\.(\d+)') {
        Write-Ok "$pyVersion gefunden"
        $pythonInstalled = $true
    }
} catch {}

if (-not $pythonInstalled) {
    try {
        $pyVersion = & python3 --version 2>$null
        if ($pyVersion -match 'Python 3') {
            Write-Ok "$pyVersion gefunden (python3)"
            $pythonInstalled = $true
        }
    } catch {}
}

if (-not $pythonInstalled -and -not $SkipPythonInstall) {
    Write-Warn "Python 3 nicht gefunden"
    Write-Info "ARGUS Backend benoetigt Python 3.10+. Installiere via winget..."
    
    try {
        $null = & winget --version 2>$null
        & winget install Python.Python.3.12 --accept-package-agreements --accept-source-agreements --silent 2>$null
        $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" + [System.Environment]::GetEnvironmentVariable("Path", "User")
        $pyVersion = & python --version 2>$null
        Write-Ok "$pyVersion installiert"
        $pythonInstalled = $true
    } catch {
        Write-Warn "Python konnte nicht automatisch installiert werden"
        Write-Info "ARGUS Backend funktioniert ohne Python nicht."
        Write-Info "Manuell installieren: https://www.python.org/downloads/"
    }
} elseif (-not $pythonInstalled) {
    Write-Warn "Python nicht gefunden — ARGUS Backend nicht verfuegbar"
}

# ═══════════════════════════════════════════
# 4. PROJEKTVERZEICHNIS
# ═══════════════════════════════════════════

Write-Step "Pruefe Projektverzeichnis..."

$projectRoot = $PSScriptRoot
if (-not $projectRoot) { $projectRoot = Get-Location }

$packageJson = Join-Path $projectRoot "package.json"
if (-not (Test-Path $packageJson)) {
    Write-Fail "package.json nicht gefunden in: $projectRoot"
    Write-Info "Bitte fuehren Sie dieses Skript im Sentinel-Projektordner aus."
    exit 1
}

Write-Ok "Projektverzeichnis: $projectRoot"

# ═══════════════════════════════════════════
# 5. .ENV DATEI
# ═══════════════════════════════════════════

Write-Step "Pruefe .env Konfiguration..."

$envFile = Join-Path $projectRoot ".env"
$envExample = Join-Path $projectRoot ".env.example"

if (Test-Path $envFile) {
    Write-Ok ".env Datei existiert bereits"
} elseif (Test-Path $envExample) {
    Copy-Item $envExample $envFile
    Write-Ok ".env aus .env.example erstellt"
    Write-Info "Bitte API-Keys in .env eintragen (siehe docs/API_KEYS_GUIDE.md)"
    Write-Info "Sentinel funktioniert auch ohne API-Keys — nur externe IP-Lookups sind deaktiviert."
} else {
    Write-Warn "Keine .env.example gefunden — erstelle leere .env"
    "# Sentinel API Keys — siehe docs/API_KEYS_GUIDE.md" | Out-File $envFile -Encoding utf8
}

# ═══════════════════════════════════════════
# 6. NPM ABHÄNGIGKEITEN
# ═══════════════════════════════════════════

Write-Step "Installiere npm-Abhaengigkeiten..."

$nodeModules = Join-Path $projectRoot "node_modules"
if (Test-Path $nodeModules) {
    Write-Info "node_modules existiert bereits — pruefe auf Updates..."
}

try {
    Push-Location $projectRoot
    & npm install 2>&1 | ForEach-Object {
        if ($_ -match "added|removed|up to date|packages") { Write-Info $_ }
    }
    Write-Ok "npm-Abhaengigkeiten installiert"
} catch {
    Write-Fail "npm install fehlgeschlagen: $_"
    exit 1
} finally {
    Pop-Location
}

# Native Module (better-sqlite3) rebuild für Electron
Write-Step "Rebuilde native Module fuer Electron..."
try {
    Push-Location $projectRoot
    & npx @electron/rebuild -f -w better-sqlite3 classic-level 2>&1 | ForEach-Object {
        if ($_ -match "rebuild|compiled|built") { Write-Info $_ }
    }
    Write-Ok "Native Module fuer Electron gebaut (better-sqlite3, classic-level)"
} catch {
    Write-Warn "Native-Module-Rebuild fehlgeschlagen — SQLite-Features koennten eingeschraenkt sein"
    Write-Info "Manuell versuchen: npx @electron/rebuild -f -w better-sqlite3 classic-level"
} finally {
    Pop-Location
}

# ═══════════════════════════════════════════
# 7. ARGUS BACKEND (Python)
# ═══════════════════════════════════════════

$argusDir = Join-Path $projectRoot "ARGUS"
if ((Test-Path $argusDir) -and $pythonInstalled) {
    Write-Step "Konfiguriere ARGUS Backend..."
    
    $argusReqs = Join-Path $argusDir "requirements.txt"
    if (Test-Path $argusReqs) {
        try {
            Push-Location $argusDir
            & python -m pip install -r requirements.txt --quiet 2>&1 | Out-Null
            Write-Ok "ARGUS Python-Abhaengigkeiten installiert"
        } catch {
            Write-Warn "ARGUS pip install fehlgeschlagen"
        } finally {
            Pop-Location
        }
    }
    
    # ARGUS .env
    $argusEnv = Join-Path $argusDir ".env"
    $argusEnvExample = Join-Path $argusDir ".env.example"
    if (-not (Test-Path $argusEnv) -and (Test-Path $argusEnvExample)) {
        Copy-Item $argusEnvExample $argusEnv
        Write-Ok "ARGUS .env erstellt"
    }
} else {
    Write-Info "ARGUS Backend uebersprungen (Python nicht verfuegbar oder ARGUS-Ordner fehlt)"
}

# ═══════════════════════════════════════════
# 8. BUILD
# ═══════════════════════════════════════════

if (-not $SkipBuild) {
    Write-Step "Baue Sentinel (TypeScript + Webpack)..."
    
    try {
        Push-Location $projectRoot
        
        # TypeScript Typcheck
        Write-Info "TypeScript Typcheck..."
        & npx tsc --noEmit 2>&1 | ForEach-Object {
            if ($_ -match "error") { Write-Warn $_ }
        }
        
        # Webpack Build (3 configs: preload, main, renderer)
        Write-Info "Webpack Build (3 Bundles)..."
        & npm run build 2>&1 | ForEach-Object {
            if ($_ -match "compiled|error|ERROR") { Write-Info $_ }
        }
        
        # Prüfe ob dist existiert
        $distMain = Join-Path $projectRoot "dist\main\main.js"
        if (Test-Path $distMain) {
            Write-Ok "Build erfolgreich — dist/main/main.js erstellt"
        } else {
            Write-Fail "Build fehlgeschlagen — dist/main/main.js nicht gefunden"
            exit 1
        }
    } catch {
        Write-Fail "Build fehlgeschlagen: $_"
        exit 1
    } finally {
        Pop-Location
    }
} else {
    Write-Info "Build uebersprungen (--SkipBuild)"
}

# ═══════════════════════════════════════════
# 9. FERTIG
# ═══════════════════════════════════════════

Write-Host ""
Write-Host "  ╔═══════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "  ║         SENTINEL SETUP ABGESCHLOSSEN          ║" -ForegroundColor Green
Write-Host "  ╚═══════════════════════════════════════════════╝" -ForegroundColor Green
Write-Host ""
Write-Ok "Sentinel ist bereit!"
Write-Host ""
Write-Info "Starten mit:"
Write-Info "  npm start                    — Sentinel starten"
Write-Info "  npm run dev                  — Build + Start"
Write-Info ""
Write-Info "Als Administrator starten (empfohlen):"
Write-Info "  Rechtsklick PowerShell -> 'Als Administrator ausfuehren'"
Write-Info "  cd $projectRoot"
Write-Info "  npm start"
Write-Host ""
Write-Info "API-Keys konfigurieren:"
Write-Info "  Bearbeite .env (siehe docs/API_KEYS_GUIDE.md)"
Write-Info "  Sentinel funktioniert auch ohne Keys — nur IP-Lookups sind dann deaktiviert."
Write-Host ""

# Auto-Start
if (-not $SkipBuild -and -not $NoBrowser) {
    Write-Step "Starte Sentinel..."
    try {
        Push-Location $projectRoot
        & npm start
    } catch {
        Write-Warn "Sentinel konnte nicht automatisch gestartet werden"
        Write-Info "Manuell starten: npm start"
    } finally {
        Pop-Location
    }
}
