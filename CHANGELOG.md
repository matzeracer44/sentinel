# Changelog / Änderungsprotokoll

---

## [3.5.0] — 2026-02-17

### Neue Funktionen / New Features

#### Threat Intelligence Automation
- **Automatische YARA-Scans**: Überwacht Downloads, Temp und Startup-Ordner im Hintergrund (konfigurierbar).
  *Automatic YARA scans monitoring Downloads, Temp, and Startup folders in background.*
- **Automatische IoC-Netzwerkprüfung**: Aktive Verbindungen werden gegen IoC-Feeds geprüft.
  *Active connections checked against IoC feeds automatically.*
- **Automatische Feed-Synchronisation**: abuse.ch und MISP-Feeds werden regelmäßig aktualisiert.
  *abuse.ch and MISP feeds synced on configurable intervals.*
- **Dashboard-Karte**: Prominente Threat-Intel-Automations-Karte mit Echtzeit-Status und Ein-Klick-Steuerung.
  *Prominent Dashboard card with real-time status and one-click controls.*

#### Dateiverschlüsselung — Drag & Drop
- **Drag & Drop Verschlüsselung**: Dateien per Drag & Drop oder Dateiauswahl-Dialog verschlüsseln.
  *Encrypt files via drag & drop or file picker dialog.*
- **In-Place Verschlüsselung**: Original wird durch `.sentinel`-Datei ersetzt (kein Kopieren in Vault-Ordner).
  *In-place encryption: original replaced by .sentinel file (no vault-dir copy).*
- **In-Place Entschlüsselung**: `.sentinel`-Datei wird zur Originaldatei zurückgewandelt.
  *In-place decryption: .sentinel restored to original file.*
- **AES-256-GCM + PBKDF2**: Militärische Verschlüsselung mit passwortbasierter Schlüsselableitung (100.000 Iterationen).
  *Military-grade encryption with password-based key derivation (100k iterations).*

### Behoben / Bug Fixes

#### Hardening-Audit Falsch-Negative
- **Windows-Firewall**: `Get-NetFirewallProfile` fiel ohne Admin-Rechte aus. Fallback auf `netsh advfirewall show allprofiles state` hinzugefügt. Akzeptiert `Enabled === 1` (nicht nur `true`).
  *Firewall check now has netsh fallback for non-admin. Accepts Enabled===1.*
- **Windows Defender**: `Get-MpComputerStatus` JSON-Parsing verbessert. Fallback auf `Get-Service WinDefend`. Signatur-Alter-Schwelle von 3 auf 7 Tage erhöht.
  *Defender check improved JSON parsing, service fallback, signature age threshold 3→7 days.*
- **BitLocker**: Windows Home (kein BitLocker) wird jetzt als `warn` mit reduziertem Gewicht (5) statt `fail` (10) gewertet.
  *BitLocker on Windows Home now warn with reduced weight instead of fail.*
- **PowerShell Timeout**: 8s → 12s für langsamere Ersterkennung.
  *PS timeout increased 8s→12s for slower first-run detection.*
- **Alle Labels**: Alle Hardening-Check-Namen und Details vollständig auf Deutsch übersetzt.
  *All hardening check names and details translated to German.*

#### Vault-Seite — IP Whitelist entfernt
- **IP-Whitelist** aus dem ARGUS-Verschlüsselungs-Tab entfernt — gehört nicht auf die Tresor-Seite. Ersetzt durch ARGUS-Backend-Status-Anzeige.
  *Removed IP whitelist from ARGUS encryption tab — replaced with ARGUS backend status display.*

#### Adaptive Zugriffschutz
- **Activity-Log-Eintrag**: Toggle-Aktivierung/-Deaktivierung wird jetzt im Aktivitätslog protokolliert.
  *Toggle enable/disable now logged in activity log.*

### Sicherheit / Security

- **DSGVO Art.32**: Dateiverschlüsselung AES-256-GCM mit PBKDF2 (100.000 Iterationen), alle Daten lokal ✅
- **Keine Secrets im Repo**: `.env` gitignored, `secedit.jfm`/`.sdb` aus Git entfernt, `.env.example` enthält nur Platzhalter ✅
- **Electron-Sicherheit**: `nodeIntegration=false`, `contextIsolation=true`, `sandbox=true` ✅
- **IPC-Integrität**: Alle IPC-Kanäle über `contextBridge`, Zod-Validierung für kritische Kanäle ✅
- **Build**: tsc 0 Fehler, webpack 3/3 kompiliert, 92/92 Sicherheitstests bestanden ✅

### Geänderte Dateien / Modified Files
- `src/main/services/threatIntelAutomation.ts` — Neuer Automation-Engine
- `src/main/main.ts` — IPC-Handler für Threat-Auto + Datei-Verschlüsselung in-place + Datei-Dialog
- `src/preload/preload.ts` — `threatAuto` + `vault.selectFiles`/`selectOutputDir` IPC-Kanäle
- `src/renderer/pages/Dashboard.tsx` — Threat-Intel-Automations-Karte
- `src/renderer/pages/VaultPage.tsx` — Drag & Drop Dateiverschlüsselung + IP-Whitelist entfernt
- `src/renderer/i18n/de.ts` — Labels Dateiverschlüsselung
- `src/renderer/i18n/en.ts` — Labels File Encryption
- `src/main/services/system/hardeningAudit.ts` — Firewall/Defender Falsch-Negative + deutsche Labels
- `.gitignore` — `secedit.*`, `*.jfm`, `*.sdb`, `tests/test-report-*.md`

---

## [3.4.0] — 2026-02-15

### Behoben / Bug Fixes

#### USB-Geräte dupliziert im Dashboard
- **Root Cause**: `Get-PnpDevice -Class USB` gibt mehrere Einträge mit gleichem `FriendlyName` zurück (z.B. USB Root Hub, Host Controller).
  *Get-PnpDevice returns multiple entries with the same FriendlyName.*
- **Fix**: Deduplizierung per `Set<string>` nach Gerätename (case-insensitive) in `hardwareDiscovery.ts`.
  *Deduplicate by device name using Set in hardwareDiscovery.ts.*

#### Systemzustand nicht mit Scans verbunden
- **Root Cause**: Der Systemzustand-Score im Dashboard war ein isolierter Hardening-Audit, nicht verknüpft mit dem Deep Scan oder System-Health-Daten.
  *Systemzustand score was an isolated hardening audit, disconnected from deep scan and system health.*
- **Fix**: Score wird jetzt kombiniert berechnet: **40% Hardening-Audit + 50% Full Scan + 10% System Health**. Hardening-Audit läuft automatisch beim Laden des Dashboards. Hinweis "Vollst. Scan f. genauen Wert erforderlich" wenn kein Scan vorhanden.
  *Score now computed as weighted combination: 40% hardening + 50% full scan + 10% system health. Auto-runs on Dashboard mount. Shows hint when no scan available.*

#### Keine Suchfunktion in Prozesse-Tab + Liste begrenzt
- **Root Cause**: Prozesse-Tab im Netzwerkmonitor hatte keine Suchleiste. Backend limitierte auf 50 Prozesse, Frontend auf 100.
  *Processes tab had no search bar. Backend limited to 50, frontend to 100.*
- **Fix**: Suchfeld hinzugefügt (Name oder PID). Backend-Limit `.slice(0, 50)` entfernt. Frontend `.slice(0, 100)` durch Suchfilter ersetzt. Anzeige "X / Y Prozesse".
  *Added search input (name or PID). Removed backend .slice(0,50). Replaced frontend .slice(0,100) with search filter. Shows "X / Y processes".*

#### ARGUS zeigt "Offline" in Einstellungen obwohl online
- **Root Cause**: Einstellungen nutzten `getHealthInfo()` (gecachter Sync-Status), während die Statusleiste `getHealthInfoLive()` (aktiver HTTP-Ping) verwendete. Gecachter Status war oft veraltet.
  *Settings used getHealthInfo() (cached sync status) while status bar used getHealthInfoLive() (active HTTP ping). Cached status was often stale.*
- **Fix**: IPC-Handler `IPC.VAULT.ARGUS_HEALTH` von `getHealthInfo()` auf `getHealthInfoLive()` umgestellt.
  *Switched IPC handler from getHealthInfo() to getHealthInfoLive().*

### Performance / Async Conversion (abgeschlossen)
- **IPC-Handler konvertiert**: `shieldHandlers.ts`, `firewallHandlers.ts`, `networkHandlers.ts`, `systemHandlers.ts`, `dnsHandlers.ts` — alle `execSync` Aufrufe zu async `exec`/`execFile` mit Promises konvertiert.
  *All remaining IPC handler sync calls converted to async.*
- **Service-Dateien konvertiert**: `securityData.ts`, `firewallSafety.ts`, `systemPrerequisites.ts`, `systemData.ts`, `hardwareDiscovery.ts`, `tweaksManager.ts`
  *Service files converted from sync to async.*

### Geprüft / Verified
- **DSGVO**: 5 externe IP-Lookup-Pfade hinter `isExternalIpLookupAllowed()` geprüft ✅
- **Sicherheit**: `nodeIntegration=false`, `contextIsolation=true`, `sandbox=true`, keine hardcodierten Keys ✅
- **INSTALL.bat + setup.ps1**: Node 22 LTS, Python 3.12, native Rebuild, .env, Build, Start ✅
- **Build**: tsc 0 Fehler + webpack 3/3 kompiliert ✅

### Geänderte Dateien / Modified Files
- `src/main/services/system/hardwareDiscovery.ts` — USB-Deduplizierung
- `src/renderer/pages/Dashboard.tsx` — Systemzustand kombinierter Score + Auto-Audit
- `src/renderer/pages/NetworkPage.tsx` — Prozess-Suchfeld + Limit entfernt
- `src/main/ipc/networkHandlers.ts` — Backend-Prozesslimit entfernt
- `src/main/ipc/vaultHandlers.ts` — ARGUS Health → getHealthInfoLive()
- `src/main/ipc/systemHandlers.ts` — await für async execPsJson/getDiskPercent
- `src/main/ipc/shieldHandlers.ts` — execSync → async runShellCmd
- `src/main/ipc/firewallHandlers.ts` — execSync → async runNetsh
- `src/main/ipc/dnsHandlers.ts` — execSync → async execAsync
- `src/main/services/securityData.ts` — execSync → async execAsync
- `package.json` — v3.4.0

---

## [3.3.3] — 2026-02-15

### Kritische Fixes / Critical Fixes

#### Netzwerkmonitor Prozesse-Tab leer (0 Prozesse)
- **Root Cause**: `Get-Process` greift auf `.TotalProcessorTime`, `.Path`, `.Description` zu — wirft Access Denied auf Systemprozesse (System, Idle, smss, csrss). Gesamtes PS-Script schlägt fehl → catch gibt `[]` zurück.
  *Get-Process accessing TotalProcessorTime/Path/Description throws Access Denied on system processes. Entire PS script fails → catch returns []*
- **Fix**: Jede Property-Abfrage in individuellem `try{}catch{}` mit sicheren Defaults. `$ErrorActionPreference='SilentlyContinue'` am Script-Anfang.
  *Each property access wrapped in individual try/catch with safe defaults. SilentlyContinue at script top.*
- **Bonus**: `execSync` (blockiert Main-Thread) → async `execFile` mit `EncodedCommand` (kein cmd.exe, kein Thread-Blocking).
  *Converted from blocking execSync to async execFile with EncodedCommand.*

#### Tiefenscan Timeout (120s zu kurz)
- **Root Cause**: 120s Timeout für 5 sequentielle PS-schwere Scan-Module (Kernel → EDR → Network → Performance → Privacy), je 10-15 PowerShell-Befehle.
  *120s timeout for 5 sequential PS-heavy scan modules, each running 10-15 PS commands.*
- **Fix**: Timeout auf 300s (5 Min) erhöht — in `main.ts` (Server) UND `Dashboard.tsx` (Client).
  *Timeout increased to 300s in both main.ts (server) and Dashboard.tsx (client).*

#### Scan-Fix ETIMEDOUT (`spawnSync cmd.exe`)
- **Root Cause**: `scan-apply-fix` Handler nutzte `execSync` (spawnt cmd.exe als Shell). `edr-syscall` Fix enthielt `sfc /verifyonly` (dauert 10+ Minuten) → 30s Timeout überschritten.
  *scan-apply-fix used execSync (spawns cmd.exe). edr-syscall fix included sfc /verifyonly (10+ minutes) → exceeded 30s timeout.*
- **Fix**: Gesamten `scan-apply-fix` auf async `execFile` mit `EncodedCommand` umgestellt (kein cmd.exe, kein Shell). Timeout auf 60s erhöht. USB-Pre-Check ebenfalls async.
  *Converted entire scan-apply-fix to async execFile with EncodedCommand (no cmd.exe, no shell). Timeout 60s. USB pre-check also async.*

#### HVCI Fix "Funktion nicht kompatibel"
- **Root Cause**: `edr-syscall` Fix versuchte HVCI zu aktivieren ohne Hardware-Kompatibilitätsprüfung. `sfc /verifyonly` (kein Fix, nur Diagnose) blockierte.
  *edr-syscall attempted HVCI without hardware compatibility check. sfc /verifyonly (diagnostic only) blocked.*
- **Fix**: Neuer Fix prüft VBS-Kompatibilität via `Win32_DeviceGuard` + `Win32_Processor.VirtualizationFirmwareEnabled`. Bei inkompatibler Hardware wird mit klarer Fehlermeldung abgebrochen. `sfc /verifyonly` entfernt, ETW Syscall-Tracing hinzugefügt.
  *New fix checks VBS compatibility. Aborts with clear error on incompatible hardware. Removed sfc, added ETW syscall tracing.*

#### Hardware ID Fix (`Set-Acl` Fehler)
- **Root Cause**: `Get-Acl`/`Set-Acl` Cmdlets benötigen `Microsoft.PowerShell.Security` Modul, das bei `-NoProfile` nicht automatisch geladen wird.
  *Get-Acl/Set-Acl require Microsoft.PowerShell.Security module which doesn't auto-load with -NoProfile.*
- **Fix**: Umgeschrieben auf .NET `Microsoft.Win32.Registry` API mit explizitem `Import-Module`. Apply + Undo-Befehle in `main.ts` und `fixSafety.ts` aktualisiert.
  *Rewritten to .NET Registry API with explicit Import-Module. Both apply and undo commands updated.*

### Geprüft / Verified (Full Audit)
- **IPC**: 170+ Kanäle geprüft — alle Preload-Channels haben Main-Handler, keine Ghost-Channels
- **Pages**: Alle 9 Seiten (Dashboard, Firewall, Intel, Network, DNS, System, Vault, Automation, Settings) verifiziert
- **Configs**: package.json, tsconfig.json, 3× webpack, electron-builder, .env.example
- **GitHub**: README.md (bilingual), CHANGELOG.md, LICENSE (MIT), CONTRIBUTING.md, docs/API_KEYS_GUIDE.md
- **INSTALL**: INSTALL.bat + setup.ps1 — Node.js, Python, native Rebuild, .env, Build, Start
- **Secrets**: 0 hardcoded API Keys/Passwörter im Quellcode
- **Stale**: 0 tote Imports, 0 Referenzen zu gelöschten Modulen
- **Assets**: 7 Icon-Dateien vorhanden
- **Build**: tsc 0 Fehler + webpack 3/3 kompiliert

### Performance / Async Conversion
- **37 blocking `spawnSync`/`execSync` Aufrufe** in `main.ts` zu async `execFile`/`execPromise` konvertiert
  *37 blocking spawnSync/execSync calls in main.ts converted to async execFile/execPromise*
- **Betroffene Handler**: `get-real-system-data` (4→1 PS-Aufruf), `forge-get-startup-items`, `forge-get-windows-services`, `sentinel-eventlog-get-security`, `sentinel-eventlog-get-alerts`, `sentinel-hardening-get-score`, `sentinel-portscan-run`, `forge-get-top-cpu-processes`, `forge-get-cpu-core-count`, `forge-backup-services-state`, `forge-get-drive-info`, `get-startup-apps`, `get-services`, `get-disk-info`, `analyze-disk`, `get-temperatures`, `get-security-status`, `get-processes-enhanced`, `get-startup-programs`, `execute-quick-action` (8 Aktionen), `get-system-health` (3 Scores), `get-system-stats`, `enable-firewall`, `enable-uac`, `shield-enable-firewall-rule`, `shield-update-firewall-rule`, `shield-unblock-port`, `shield-block-subnet`, `forge-disable-all-bloatware`, `forge-restore-services-state`
- **Verbleibende sync-Aufrufe** (5): Startup-Init (`getSystemInfo`, `getOSInfo`, `checkAdminSync`, `icacls`, `reg add RUNASADMIN`) — absichtlich synchron, laufen einmalig vor Fensteröffnung
  *Remaining 5 sync calls are startup-only init that must complete before window opens*
- **Ergebnis**: Main-Thread wird nie durch IPC-Handler blockiert → kein UI-Einfrieren unter Last
  *Result: Main thread never blocked by IPC handlers → no UI freezing under load*

### Geänderte Dateien / Modified Files
- `src/main/ipc/shieldHandlers.ts` — Process-Liste: per-property try/catch + async execFile + EncodedCommand
- `src/main/main.ts` — 37 sync→async Konvertierungen, Scan-Timeout 300s, edr-syscall VBS-Check, priv-hwid .NET Registry, scan-apply-fix async
- `src/renderer/pages/Dashboard.tsx` — Client-Timeout 300s
- `src/shared/fixSafety.ts` — edr-syscall + priv-hwid Undo-Befehle aktualisiert
- `CONTRIBUTING.md` — Stale `src/engines/` Referenz entfernt
- `package.json` — v3.3.3

---

## [3.3.2] — 2026-02-15

### Kritische Fixes / Critical Fixes

#### classic-level Crash behoben (App startete nicht)
- **Root Cause**: CopyWebpackPlugin kopierte `classic-level` + 8 Subdependencies nach `dist/main/node_modules/`, aber die tiefe Abhängigkeitskette war unvollständig (`maybe-combine-errors` fehlte).
  *CopyWebpackPlugin copied classic-level + 8 sub-deps to dist, but the deep dependency tree was incomplete.*
- **Fix**: Alle manuellen `node_modules/` Kopien aus webpack entfernt. Node.js löst native Module nun vom Projekt-Root `node_modules/` auf (funktioniert, da `npm start` vom Projekt-Root ausgeführt wird).
  *Removed all manual node_modules copies from webpack. Node.js resolves native modules from project root node_modules/ naturally.*
- **Phantom-Dep entfernt**: `leveldown` war in package.json + setup.ps1 referenziert, existierte aber nicht in node_modules und wurde nirgends importiert.
  *Removed phantom leveldown dependency — listed but never installed or imported.*

#### Duplicate vpnDetector konsolidiert
- **Alt (gelöscht)**: `src/main/services/vpnDetector.ts` — sync `spawnSync` Version
- **Behalten**: `src/main/services/network/vpnDetector.ts` — async `execFile` Version
- **main.ts Fix**: Import + `await` für async VpnStatus-Interface (`adapter` statt `adapters`)

#### Stale Files gelöscht
- `src/main/workers/` — leeres Verzeichnis
- `src/renderer/index.html` — stale Duplikat (webpack nutzt `public/index.html`)
- `src/main/services/shared/performanceProfile.ts` — nicht importiert, hardcoded Hardware-Specs

### Verbesserungen / Improvements

#### electron-builder Production Config
- **files**: Native Module (`better-sqlite3`, `classic-level` + 7 Deps) explizit in `files[]` für NSIS Installer
- **extraResources**: ARGUS Backend (ohne `__pycache__`, `.pyc`, `logs/`, `.env`)

#### .gitignore Fix
- `package-lock.json` wird jetzt getrackt (vorher ignoriert) — ermöglicht reproduzierbare Builds auf frischen Hosts

### Geprüft / Verified
- **DSGVO**: Art. 5 (PII-Entfernung), Art. 6 (IP-Lookup-Gate), Art. 13 (Datenschutz-UI), Art. 17 (3 Lösch-Handler), Art. 32 (CSP/Sandbox/AES-256-GCM)
- **Scans**: Alle 5 Scanner-Module (Kernel, EDR, Network, Performance, Privacy) — Imports, IPC-Handler, Preload-Exposure verifiziert
- **Build**: tsc 0 Fehler + webpack 3/3 kompiliert
- **Launch**: App startet, UAC-Elevation, Single-Instance-Lock funktioniert

### Geänderte Dateien / Modified Files
- `webpack.main.config.js` — Entfernt 9 CopyWebpackPlugin node_modules Patterns, nur assets/ bleibt
- `package.json` — v3.3.2, entfernt leveldown, electron-builder files + extraResources
- `setup.ps1` — entfernt leveldown aus native rebuild
- `src/main/main.ts` — vpnDetector Import fix (network/vpnDetector, await, adapter statt adapters)
- `.gitignore` — package-lock.json getrackt

---

## [3.3.1] — 2026-02-15

### Production Hardening / Produktionshärtung

#### Dead Dependency Purge (11 Pakete entfernt)
- **Entfernt / Removed**: `claude-code`, `node-powershell`, `react-hot-toast`, `chokidar`, `winston`, `dns-packet`, `@emotion/is-prop-valid`, `@emotion/styled`, `fs-extra`, `recharts`, `react-window`, `date-fns`, `lodash`, `@types/react-window`, `@types/fs-extra`, `@types/lodash`
- Keines dieser Pakete wurde im Quellcode importiert — spart ~120MB bei `npm install` auf frischen Systemen.
  *None of these packages were imported in source — saves ~120MB on fresh npm install.*

#### Empty Catch Block Final Purge (21 verbleibende behoben)
- **main.ts** (5): `dialog.showErrorBox` + `webContents.send` — beschreibende Kommentare
- **activityLog.ts** (4): Console-Override-Catches — Kommentar erklärt Rekursionsschutz
- **hardwareDiscovery.ts** (7): PS-Catches für TPM, SecureBoot, BitLocker, Thermal, Monitor — PS-Kommentare
- **eventLogAnalyzer.ts** (3): PS-Catches für Event-Log-Abfragen — PS-Kommentare
- **guardianPlaybookEngine.ts** (1): `child.kill()` Timeout — Kommentar
- **shieldData.ts** (1): PS Process-Kill — Kommentar
- **profiler.ts** (3): `mkdirSync`, `clearInterval`, `monitor.disable` — Kommentare
  *21 remaining empty catch blocks across 7 files documented with descriptive comments. Zero empty catches in entire codebase.*

#### INSTALL.bat + setup.ps1 — Frisch-Host-Kompatibilität
- **Native Module Rebuild** erweitert: `better-sqlite3` + `classic-level` + `leveldown` (vorher nur better-sqlite3)
  *Native module rebuild now includes all 3 native deps instead of just better-sqlite3.*
- **Node.js URL** aktualisiert auf v22.14.0 LTS (vorher hardcoded v20.11.0)
- **electron-builder Icon** korrigiert: `assets/icon.png` statt nicht existierendem `public/icon.ico`
- **npm script** `native:rebuild` aktualisiert für alle 3 Native-Module
- **Setup-Banner** auf v3.0 aktualisiert

#### Stale Configuration Cleanup
- **Entfernt / Removed**: `@engines` Alias aus `webpack.renderer.config.js` (war nach Löschung von `src/engines/` übrig geblieben)
- **public/index.html** Titel: `Sentinel 2.0` → `Sentinel`

### Neu / New

#### Dashboard Scan-Fortschritt
- **Preload**: `onScanProgress` Listener für `sentinel-scan-progress` Events
- **Dashboard**: Echtzeit-Anzeige des aktuellen Scan-Moduls (Icon + Label + Farbe) während Deep Scan
  *Real-time scan phase indicator shows which module (Kernel, EDR, Network, Performance, Privacy) is currently scanning.*

### Geprüft / Verified
- **0 leere Catch-Blöcke** im gesamten Codebase (`grep` bestätigt)
- **0 TODO/FIXME/HACK** Kommentare
- **0 Dead Imports** referenzieren gelöschte Module
- **0 Stale Aliases** in tsconfig/webpack configs
- **Build**: tsc 0 Fehler + webpack 3/3 kompiliert
- **dist/**: main.js (669KB), renderer.js (4.8MB), index.html, 7 Icon-Dateien, Native-Module

### Geänderte Dateien / Modified Files
- `package.json` — 11 dead deps entfernt, native:rebuild + electron-builder icon fix
- `setup.ps1` — rebuild all 3 native modules, Node v22 LTS, banner v3.0
- `webpack.renderer.config.js` — stale @engines alias entfernt
- `public/index.html` — Titel korrigiert
- `src/preload/preload.ts` — onScanProgress listener
- `src/renderer/pages/Dashboard.tsx` — scanPhase state + scan progress UI
- `src/main/main.ts` — 5 catch blocks documented
- `src/main/services/activityLog.ts` — 4 catch blocks documented
- `src/main/services/profiler.ts` — 3 catch blocks documented
- `src/main/services/guardianPlaybookEngine.ts` — 1 catch block documented
- `src/main/services/shieldData.ts` — 1 catch block documented
- `src/main/services/system/hardwareDiscovery.ts` — 7 PS catch blocks documented
- `src/main/services/system/eventLogAnalyzer.ts` — 3 PS catch blocks documented

---

## [3.3.0] — 2026-02-15

### Sicherheit / Security

#### Command Injection Hardening (3 Dateien)
- **processManager.ts** — `disableStartupProgram`/`enableStartupProgram` akzeptierten unsanitisierten User-Input direkt in PowerShell-Befehlen. Behoben mit `sanitizePSArg()` + `EncodedCommand` via `execFile` (kein Shell-Durchgriff).
  *User-controlled name param injected raw into PS commands. Fixed with sanitizer + EncodedCommand via execFile.*
- **snapshotManager.ts** — Path-Traversal in `deleteSnapshot`/`getSnapshot`: User-ID wurde ohne Validierung im Dateipfad verwendet. Behoben mit `validateSnapshotId()` (nur alphanumerisch + Bindestriche).
  *Path traversal via snapshot ID. Fixed with alphanumeric-only validation.*
- **guardianPlaybookEngine.ts** — Script-Path-Traversal: `resolveScriptPath()` akzeptierte `../` in scriptId. Behoben mit Regex-Reject.
  *Script path traversal via ../. Fixed with regex reject for directory separators.*

#### Script Execution Timeout
- **guardianPlaybookEngine.ts** — `executePowerShellScript` hatte kein Timeout. Hinzugefügt: 30s Timeout mit Child-Process-Cleanup.
  *No timeout on PS script execution. Added 30s timeout with proper process kill.*

### Performance

#### Sync-to-Async Conversion (3 Dateien — Main-Thread-Blocking behoben)
- **processManager.ts** — `execSync` → async `execFile` mit `EncodedCommand`. Main-Thread wird nicht mehr blockiert.
- **cleanupData.ts** — 5 sequentielle synchrone PS-Aufrufe → async. App friert nicht mehr ein beim Scannen.
- **snapshotManager.ts** — Sync PS + `fs.readFileSync` in Schleifen → async `execFile` + `fs.promises`.

### Behoben / Fixed

#### Scan-Popup-Details — 25 fehlende Templates + 2 ID-Mappings repariert
- **25 fehlende `ID_TO_TEMPLATE` Einträge** hinzugefügt (8 Kernel, 5 EDR, 12 Performance) in `mergeCheckDetails.ts`
- **25 englische Templates** in `edrKernelPerfChecks.ts` für alle neuen Checks
- **25 deutsche Übersetzungen** in `kernelChecks.de.ts`, `edrChecks.de.ts`, `perfChecks.de.ts`
- **2 fehlerhafte ID-Mappings** repariert: `perf-ctx` → `perf-ctxswitch`, `perf-ramstability` → `perf-ramstab` (Popups funktionierten nicht)
  *25 missing templates + 2 broken ID mappings fixed. Context Switches and RAM Stability popups were silently failing.*

#### cleanupData.ts — Fehlende Downloads in Gesamtsumme
- `totalCleanableGB` fehlte `downloadSizeGB` in der Berechnung. Jetzt alle 5 Kategorien enthalten.
  *Downloads folder size was calculated but not included in totalCleanableGB sum.*

### Geprüft / Verified
- **101/101 Scanner-IDs** haben korrekte `ID_TO_TEMPLATE` Einträge (Kernel, EDR, Network, Performance, Privacy)
- **57 Service-Dateien** vollständig auditiert (Sicherheit, Performance, Funktionalität)
- **Build**: tsc 0 Fehler + webpack 3/3 kompiliert

### Geänderte Dateien / Modified Files
- `src/main/services/processManager.ts` — sanitizePSArg + async execFile
- `src/main/services/snapshotManager.ts` — validateSnapshotId + async execFile + fs.promises
- `src/main/services/cleanupData.ts` — async execFile + downloadSizeGB fix
- `src/main/services/guardianPlaybookEngine.ts` — path traversal block + 30s script timeout
- `src/main/services/scanners/mergeCheckDetails.ts` — 25 new ID mappings + 2 ID fixes
- `src/main/services/scanners/edrKernelPerfChecks.ts` — 25 new English templates
- `src/main/services/scanners/kernelChecks.de.ts` — 6 new German kernel templates
- `src/main/services/scanners/edrChecks.de.ts` — 5 new German EDR templates
- `src/main/services/scanners/perfChecks.de.ts` — 12 new German performance templates
- `package.json` — version 3.2.0 → 3.3.0

---

## [3.2.0] — 2026-02-15

### Behoben / Fixed

#### Scan-Fix-Befehle — 27 fehlende Fixes hinzugefügt
- **EDR (17 Fixes)**: `edr-syscall` (HVCI + ntdll-Verifizierung), `edr-honeypot` (Canary-Dateien), `edr-hollowing` (Process-Hollowing-Scan), `edr-reflectivedll` (DEP/CFG/SEHOP/ForceRelocate), `edr-apc` (Process-Creation-Auditing), `edr-entropy` (Controlled Folder Access), `edr-ppid` (Event 4688 + Cmd-Logging), `edr-com` (COM-CLSID-Audit), `edr-behavior` (Network Protection + PUA), `edr-apimap` (Sysmon-Status), `edr-handles` (LSASS PPL + ASR-Regel), `edr-namedpipe` (C2-Pipe-Scan), `edr-dlls` (SafeDllSearchMode), `edr-schtask` (Task-Audit), `edr-svcaudit` (Dienst-Audit), `edr-nla` (NLA für RDP), `edr-asr` (16 ASR-Regeln Audit-Modus), `edr-etwti` (ETW Threat-Intelligence)
  *17 EDR fix commands added — covers syscall integrity, honeypots, process hollowing, exploit mitigations, auditing, ASR rules*
- **Kernel (5 Fixes)**: `kernel-privesc` (UAC-Härtung + FilterAdminToken), `kernel-integrity` (SFC /scannow), `kernel-driverpaths` (Nicht-System-Treiber-Audit), `kernel-dkom` (WMI/PS Prozesszählung), `kernel-microcode` (CPU-Microcode-Status)
  *5 kernel fix commands added — privilege escalation hardening, system file checker, driver audit, DKOM detection, microcode check*
- **Netzwerk (2 Fixes)**: `net-beacon` (Beaconing-Firewall-Regel), `net-netflow` (Nicht-Standard-Port-Audit)
  *2 network fix commands added — beaconing block rule, suspicious listener audit*
- **Performance (2 Fixes)**: `perf-dpc` (USB-Energiesparen deaktivieren), `perf-memcomp` (Speicherkomprimierung basierend auf RAM)
  *2 performance fix commands added — USB power saving, memory compression optimization*

#### Fix-Sicherheitsklassifizierungen — 27 Einträge in fixSafety.ts
- **Alle 27 neuen Fixes vollständig klassifiziert**: Danger-Level (safe/caution/dangerous), whatChanges, whatCouldBreak, undoCommand, undoDescription, alle 6 Sicherheits-Flags
  *All 27 new fixes fully classified with danger levels, impact descriptions, undo commands, and 6 safety flags each*

#### Hardware-Erkennung — RAM-Anzeige repariert
- **Root Cause**: `Win32_OperatingSystem` WMI-Abfrage konnte auf manchen Systemen leer zurückkommen → RAM zeigte "0 GB (0 used / 0 free)"
  *Win32_OperatingSystem WMI query could return empty on some systems → RAM showed "0 GB (0 used / 0 free)"*
- **Fix**: Node.js `os.totalmem()` / `os.freemem()` Fallback in `hardwareDiscovery.ts` wenn WMI-Daten fehlen
  *Node.js os.totalmem()/os.freemem() fallback in hardwareDiscovery.ts when WMI data is missing*

### Geänderte Dateien / Modified Files
- `src/main/main.ts` — 27 neue SCAN_FIX_COMMANDS
- `src/shared/fixSafety.ts` — 27 neue FIX_CLASSIFICATIONS mit deutschen Beschreibungen
- `src/main/services/system/hardwareDiscovery.ts` — RAM-Fallback via Node.js os-Modul

---

## [3.1.0] — 2026-02-15

### Behoben / Fixed

#### ARGUS URL-Scanner — Falsch-Positiv-Behebung
- **Root Cause**: Renderer castete ARGUS-Antwort direkt auf `ScanResult` — `safe` war immer `undefined` (falsy) → JEDE URL zeigte „Potenziell unsicher"
  *Renderer cast ARGUS response directly to ScanResult — safe was always undefined (falsy) → EVERY URL showed "Potentially Unsafe"*
- **mapArgusResponse()**: Neue Mapping-Funktion wandelt `threat_level` → `safe: boolean`, `threat_score` → invertierter Safety-Score, `reasons` → `details`
  *New mapping function converts threat_level → safe boolean, threat_score → inverted safety score, reasons → details*
- **Phishing-Keywords**: Markennamen (google, amazon, microsoft, apple etc.) aus Phishing-Keyword-Liste entfernt — lösten False Positives auf legitimen Domains aus
  *Brand names removed from phishing keywords list — were triggering false positives on legitimate domains*
- **Marken-Impersonation**: Separate Logik prüft Markennamen NUR in Subdomains (z.B. `google.evil.com` wird markiert, `mail.google.com` NICHT)
  *Separate logic checks brand names ONLY in subdomains (e.g., google.evil.com flagged, mail.google.com NOT)*
- **Hosting-Provider-Strafe entfernt**: `is_hosting` Penalty (+1) entfernt — Google, Cloudflare, AWS sind alle Hosting-Provider
  *Hosting provider penalty removed — Google, Cloudflare, AWS are all hosting providers*
- **Schwellenwerte erhöht**: CRITICAL ≥20, MALICIOUS ≥14, SUSPICIOUS ≥8, LOW ≥3, SAFE <3 (vorher 15/10/5/2)
  *Thresholds raised: CRITICAL ≥20, MALICIOUS ≥14, SUSPICIOUS ≥8, LOW ≥3, SAFE <3 (previously 15/10/5/2)*
- **Scan-Historie**: History-Einträge werden jetzt ebenfalls durch `mapArgusResponse` gemappt
  *History entries now also mapped through mapArgusResponse*

#### Scan-Check-Beschreibungen — Vollständige deutsche Übersetzung
- **91 Scan-Checks komplett übersetzt**: Netzwerk (15), Datenschutz (22), EDR (24), Kernel (15), Performance (15)
  *91 scan checks fully translated: Network (15), Privacy (22), EDR (24), Kernel (15), Performance (15)*
- **Sprachumschaltung**: `setCheckLanguage()` / `getCheckLanguage()` im Main-Prozess, IPC-Handler `sentinel-set-scan-language`
  *Language switching: setCheckLanguage()/getCheckLanguage() in main process, IPC handler sentinel-set-scan-language*
- **Automatische Sync**: Dashboard und Settings synchronisieren Sprache zum Main-Prozess vor jedem Scan
  *Automatic sync: Dashboard and Settings sync language to main process before every scan*

#### IntelPage i18n
- **buildDetailSections**: Alle Labels (Übersicht, URL, Bewertung, Sicherheitswert, Gescannt) über `t()` übersetzt
  *All labels (Overview, URL, Verdict, Safety Score, Scanned) translated via t()*
- **expandedSections**: Verwendet übersetzten Kategorienamen statt hartkodiertem `'Overview'`
  *Uses translated category name instead of hardcoded 'Overview'*
- **ScanCheckItem**: Alle Sektionsüberschriften und Buttons über `t()` übersetzt
  *All section headings and buttons translated via t()*

### Neue Dateien / New Files
- `src/main/services/scanners/checkTemplates.de.ts` — Deutsche Netzwerk- & Datenschutz-Scan-Beschreibungen
- `src/main/services/scanners/edrChecks.de.ts` — Deutsche EDR-Scan-Beschreibungen (24)
- `src/main/services/scanners/kernelChecks.de.ts` — Deutsche Kernel-Scan-Beschreibungen (15)
- `src/main/services/scanners/perfChecks.de.ts` — Deutsche Performance-Scan-Beschreibungen (15)

---

## [3.0.0] — 2026-02-15

### Hinzugefügt / Added

#### Internationalisierung / Internationalization (i18n)
- **Vollständige deutsche Übersetzung** — 500+ Strings für alle 9 Seiten + Sidebar + Gemeinsame Komponenten
  *Complete German translation — 500+ strings for all 9 pages + sidebar + common components*
- **Sprachumschaltung** — Deutsch/Englisch in Einstellungen, Auswahl wird in localStorage gespeichert
  *Language toggle — German/English in Settings, choice persisted in localStorage*
- **useTranslation** in allen Seiten: Dashboard, Firewall, Network, Intel, DNS, System, Vault, Automation, Settings
  *useTranslation wired into all pages*

#### DSGVO / GDPR Compliance
- **Einwilligungspflichtige IP-Lookups** — Externe ipinfo.io-Abfragen nur bei aktivierter Zustimmung (3 Pfade geprüft)
  *Consent-gated IP lookups — external ipinfo.io calls only when user enables them (3 paths audited)*
- **Recht auf Löschung** — Activity Log, Threat Events, Scan-Historie löschbar in Einstellungen (Art. 17 DSGVO)
  *Right to erasure — Activity log, threat events, scan history deletable in Settings (Art. 17 GDPR)*
- **Datenschutz-Panel** — Vollständige DSGVO-Informationen mit Speicherübersicht in Einstellungen
  *Privacy panel — Full GDPR information with storage overview in Settings*
- **Keine Telemetrie** — Sentinel sendet keine Nutzungsdaten an Dritte
  *No telemetry — Sentinel sends no usage data to third parties*

#### Sicherheitshärtung / Security Hardening
- **Shell-Injection-Schutz** — Zentraler `sanitizeShellArg()` / `sanitizeShellInt()` / `sanitizeShellEnum()` in `shared/utils.ts`
  *Shell injection protection — central sanitizer functions in shared/utils.ts*
- **9 gehärtete Handler** — Firewall-Regeln, Service-Steuerung, Starteinträge, Power-Plan alle mit Eingabevalidierung
  *9 hardened handlers — firewall rules, service control, startup items, power plan all with input validation*
- **Whitelist-Validierung** — Power-Plan-GUIDs, Protokolle, Aktionen nur aus erlaubten Werten
  *Whitelist validation — power plan GUIDs, protocols, actions only from allowed values*

#### Deutsche Windows-Kompatibilität / German Windows Compatibility
- **8 Locale-Fixes** — PowerShell-Ausgaben für deutsches Windows angepasst:
  *8 locale fixes — PowerShell outputs adapted for German Windows:*
  - Firewall: `Select-String "ON"` → `Select-Object -ExpandProperty Enabled`
  - ETW: `"Running"` → `Status -eq 4` (numerisch / numeric)
  - Privilegien: `"Enabled"` → `"Enabled|Aktiviert"`
  - BCDEdit: `"Yes"` → `"Yes|Ja"`
  - WiFi: `"connect"` → `"connect|verbunden"`
  - Auditpol: `"Success and Failure"` → `"Success and Failure|Erfolg und Fehler"`
  - Schtasks: CSV-Parsing → `Get-ScheduledTask` PowerShell-Cmdlet
  - Services: `"Running"` → `.Status -eq 'Running'` (struct-basiert / struct-based)

#### Installation / Setup
- **setup.ps1** — Automatisches Setup-Skript: Node.js, Python, npm-Deps, native Rebuild, Build, Start
  *Automatic setup script: Node.js, Python, npm deps, native rebuild, build, start*
- **INSTALL.bat** — Doppelklick-Installer für einfache Installation
  *Double-click installer for easy setup*

#### Portabilität / Portability
- **Keine hardcodierten Pfade** — Alle Konfiguration über `app.getPath('userData')`, `__dirname`, `process.cwd()`
  *No hardcoded paths — all config via app.getPath('userData'), __dirname, process.cwd()*
- **Null persönliche Daten** im Quellcode — kein Benutzername, keine E-Mail, keine lokalen Pfade
  *Zero personal data in source code — no username, no email, no local paths*

---

## [2.0.0] — 2026-02-14

### Hinzugefügt / Added

#### Fix-Sicherheitssystem / Fix Safety System
- **Fix-Klassifizierung** — Jeder Scan-Fix als sicher/vorsicht/gefährlich/verboten eingestuft
  *Fix classification — every scan fix rated safe/caution/dangerous/forbidden*
- **FixConfirmDialog** — Zeigt Gefahrenstufe, Änderungen, Risiken, Undo-Anleitung vor jedem Fix
  *Shows danger level, changes, risks, undo instructions before any fix*
- **Auto-Revert** — Fixes die Internet unterbrechen werden automatisch rückgängig gemacht
  *Fixes that break internet connectivity are automatically reverted*
- **Undo-Speicher** — 24h Rollback-Fenster für alle angewandten Fixes
  *Undo store — 24h rollback window for all applied fixes*
- **Verbotene Fixes** — Gefährliche Fixes (z.B. alle Ausgehenden blockieren) dauerhaft gesperrt
  *Forbidden fixes — dangerous fixes (e.g., block all outbound) permanently blocked*

#### Benachrichtigungssystem / Notification System
- **SentinelNotification** — Eigenes Benachrichtigungssystem (ersetzt react-hot-toast)
  *Custom notification system (replaced react-hot-toast)*
- **31 leere Catch-Blöcke** in 13 Dateien durch fehlerbehandlung ersetzt
  *31 empty catch blocks in 13 files replaced with proper error handling*
- **System-Tray** — Minimieren in Tray, Balloon-Benachrichtigungen, Kontextmenü
  *Minimize to tray, balloon notifications, context menu*
- **Push-Benachrichtigungen** — Echtzeit-Bedrohungsalarme Main→Renderer
  *Real-time threat alerts Main→Renderer*

#### System-Features
- **Auto-Start** — Windows-Anmeldung mit Toggle in Einstellungen
  *Windows login item integration with Settings toggle*
- **Geplante Scans** — Automatische Hintergrund-Scans alle 6 Stunden
  *Automatic background scans every 6 hours*
- **Sicherheitsbericht-Export** — HTML/JSON-Berichterstellung mit Speicherdialog
  *HTML/JSON report generation with save dialog*
- **Einstellungen Export/Import** — Konfiguration sichern und wiederherstellen
  *Backup and restore configuration*
- **FIM-Alarme** — Dateiintegritätsmonitor mit Push-Benachrichtigungen
  *File Integrity Monitor wired to push notifications*
- **USB-Überwachung** — Echtzeit-Alarme für neue Massenspeichergeräte
  *Real-time alerts for new mass storage devices*

#### API & Sicherheit / API & Security
- **envLoader.ts** — Zentrale API-Key-Verwaltung über `.env`-Datei
  *Central API key management via .env file*
- **Aktivitätsprotokoll** — 25+ Handler loggen Aktionen (Firewall, DNS, Scan, Vault, Prozess)
  *Activity logging — 25+ handlers log actions (firewall, DNS, scan, vault, process)*

#### Design / UI
- **CSS Design System v2** — Glassmorphic Tabs, Aurora-Hover-Effekte, Gradient-Divider, Stat-Pills
  *Glassmorphic tabs, aurora hover effects, gradient dividers, stat pills*
- **Alle 9 Seiten** mit Premium-Design aufgerüstet
  *All 9 pages upgraded with premium design*

### Behoben / Fixed
- **BUG-A**: FirewallPage hat jetzt Export TXT/CSV/JSON Buttons
  *FirewallPage now has Export TXT/CSV/JSON buttons*
- **BUG-B**: Alle leeren Catch-Blöcke im Renderer durch Fehlerbehandlung ersetzt
  *All empty catch blocks in renderer replaced with proper error handling*
- **BUG-C**: Vault Ver-/Entschlüsselung korrekt über detectEncryptionSource
  *Vault encrypt/decrypt routes correctly via detectEncryptionSource*
- **BUG-D**: Scan-Offenders mit echten Daten in EDR + Netzwerk-Prüfungen
  *Scan offenders populated with real data in EDR + Network checks*
- **BUG-E**: Kill-Buttons für systemkritische Prozesse ausgeblendet
  *Kill buttons hidden for system-critical processes*
- **BUG-F**: ARGUS Singleton verifiziert — einzelner start()-Aufruf mit Mutex
  *ARGUS singleton verified — single start() call with generation mutex*
- **BUG-H**: Keine doppelten IPC-Handler gefunden
  *No duplicate IPC handlers found*
- **Firewall Direction**: `[int]`-Cast auf PS-Enum für locale-sichere Serialisierung
  *[int] cast on PS enum for locale-safe serialization*
- **VPN-Filter**: Behoben — VPN-getunnelte Verbindungen wurden fälschlich verworfen
  *Fixed — VPN-tunneled connections were incorrectly dropped*

### Sicherheit / Security
- API-Keys durch envLoader ersetzt — keine hardcodierten Schlüssel
  *API keys replaced with envLoader — no hardcoded keys*
- `.gitignore` erweitert für Secrets, persönliche Daten, ARGUS
  *.gitignore expanded for secrets, personal data, ARGUS*
- CSP erzwungen, Context Isolation aktiviert, Sandbox-Modus an
  *CSP enforced, context isolation enabled, sandbox mode on*

---

## [1.0.0] — 2026-02-10

### Hinzugefügt / Added
- **Erstveröffentlichung** mit Dashboard, Firewall, Network Monitor, Threat Intel, DNS, System, Vault, Automation
  *Initial release with Dashboard, Firewall, Network Monitor, Threat Intel, DNS, System, Vault, Automation*
- **100+ Sicherheitsprüfungen** in 5 Modulen (Netzwerk, EDR, Kernel, Datenschutz, Performance)
  *100+ security scan checks across 5 modules (Network, EDR, Kernel, Privacy, Performance)*
- **ARGUS AI Sandbox** Integration
- **AES-256-GCM** Vault-Verschlüsselung / *Vault encryption*
