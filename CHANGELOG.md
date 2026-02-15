# Changelog

## [2.0.0] — 2026-02-15

### Added
- **Fix Safety System** — Every scan fix classified (safe/caution/dangerous/forbidden)
- **FixConfirmDialog** — Shows danger level, what changes, risks, undo instructions before any fix
- **Auto-Revert** — Fixes that break internet connectivity are automatically reverted
- **Undo Store** — 24h rollback window for all applied fixes
- **Connectivity Check** — Ping + DNS + firewall outbound verified after network fixes
- **Forbidden Fix Blocking** — Dangerous fixes (e.g., block all outbound) permanently blocked
- **EDR Offenders** — Process Hollowing, WMI Persistence, PPID Spoofing, Auto-Run checks now show detailed offenders
- **Network Offenders** — Beaconing Detection and ARP checks show per-host/per-entry details
- **envLoader.ts** — Central API key management via `.env` file
- **Activity Logging** — 25+ handlers now log to activity log (firewall, DNS, scan, vault, process kill)
- **USB Device Monitoring** — Real-time alerts for new mass storage devices
- **Network Anomaly Detection** — Suspicious connection alerts (high ports, unknown processes)
- **System Tray** — Minimize to tray, balloon notifications, context menu
- **Auto-Start** — Windows login item integration with Settings toggle
- **Scheduled Scans** — Automatic background scans every 6 hours
- **Security Report Export** — HTML/JSON report generation with save dialog
- **Settings Export/Import** — Backup and restore configuration
- **Push Notifications** — Main→Renderer real-time threat alerts
- **FIM Alerts** — File Integrity Monitor wired to push notifications
- **DSGVO Compliance** — IP lookup toggle, data deletion controls, no PII in logs

### Fixed
- **BUG-A**: FirewallPage now has Export TXT/CSV/JSON buttons
- **BUG-B**: All empty catch blocks in renderer replaced with proper error handling
- **BUG-C**: Vault encrypt/decrypt routes correctly via detectEncryptionSource
- **BUG-D**: Scan offenders populated with real data in EDR + Network checks
- **BUG-E**: Kill buttons hidden for system-critical (forbidden) and Sentinel (dangerous) processes
- **BUG-F**: ARGUS singleton verified — single start() call with generation mutex
- **BUG-H**: No duplicate IPC handlers found

### Security
- Hardcoded API keys replaced with envLoader
- .gitignore expanded for secrets, personal data, ARGUS
- CSP enforced, context isolation enabled, sandbox mode on

## [1.0.0] — 2026-02-10

### Added
- Initial release with Dashboard, Firewall, Network Monitor, Threat Intel, DNS, System, Vault, Automation
- 100+ security scan checks across 5 modules
- ARGUS AI sandbox integration
- AES-256-GCM Vault encryption
