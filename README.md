<div align="center">
  <h1>🛡 SENTINEL</h1>
  <p><strong>Unified Security Suite for Windows</strong></p>

  <p>
  🇩🇪 Echtzeit-Bedrohungsanalyse, Netzwerk-Monitoring, Firewall-Management,
  Datenschutz-Härtung und Systemsicherheit — alles in einer Desktop-App.<br>
  🇬🇧 Real-time threat monitoring, network analysis, firewall management,
  privacy hardening, and system security — all in one desktop app.
  </p>

  <img src="https://img.shields.io/badge/Platform-Windows%2010%2F11-blue" />
  <img src="https://img.shields.io/badge/Electron-40-green" />
  <img src="https://img.shields.io/badge/TypeScript-5-blue" />
  <img src="https://img.shields.io/badge/React-18-cyan" />
  <img src="https://img.shields.io/badge/Language-DE%20%2F%20EN-orange" />
  <img src="https://img.shields.io/badge/DSGVO%20%2F%20GDPR-Compliant-green" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" />
</div>

---

## Features / Funktionen

| Module | 🇩🇪 Deutsch | 🇬🇧 English |
|--------|------------|-------------|
| **Shield / Firewall** | Echtzeit-Regelverwaltung, IP/Port/Subnetz-Blockierung, Undo/Redo | Real-time rule management, IP/port/subnet blocking, undo/redo |
| **Network Monitor** | Live-Verbindungen, TLS-Inspektion, Prozess-Tracking, Beaconing-Erkennung | Live connections, TLS inspection, process tracking, beaconing detection |
| **ARGUS AI Sandbox** | URL-Scanning, Bedrohungsklassifizierung, Verhaltensanalyse | URL scanning, threat classification, behavioral analysis |
| **Threat Intelligence** | Guardian Stories, Anomalie-Erkennung, automatisierte Playbooks | Guardian stories, anomaly detection, automated playbooks |
| **Vault** | AES-256-GCM-Verschlüsselung, sichere Notizen, Passwort-Generator, Datei-Shredder | AES-256-GCM encryption, secure notes, password generator, file shredder |
| **Ghost / DNS & Privacy** | DNS-Konfiguration, Hosts-Verwaltung, Telemetrie-Kontrolle | DNS configuration, hosts management, telemetry control |
| **Forge / System** | Hardware-Diagnose, Performance-Tuning, Health-Scoring | Hardware diagnostics, performance tuning, health scoring |
| **Security Scans** | 101 Prüfungen in 5 Modulen, 67+ automatische Fixes mit Sicherheitsklassifizierung | 101 checks across 5 modules, 67+ automated fixes with safety classification |
| **DSGVO / GDPR** | Alle Daten lokal, externe Lookups nur mit Einwilligung, Recht auf Löschung | All data local, external lookups consent-gated only, right to erasure |
| **i18n** | Vollständige deutsche und englische Oberfläche | Complete German and English UI |

---

## Schnellstart / Quick Start

### 🇩🇪 Automatische Installation (empfohlen)

Doppelklick auf `INSTALL.bat` oder in PowerShell (als Administrator):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup.ps1
```

Das Setup-Skript:
1. Prüft Windows 10/11, PowerShell 5.1+
2. Installiert Node.js (LTS) falls nicht vorhanden
3. Installiert Python 3 falls nicht vorhanden (für ARGUS)
4. Installiert alle npm-Abhängigkeiten
5. Erstellt `.env` aus `.env.example`
6. Baut Sentinel (TypeScript + Webpack)
7. Startet Sentinel

### 🇬🇧 Automatic Installation (recommended)

Double-click `INSTALL.bat` or run in PowerShell (as Administrator):

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\setup.ps1
```

The setup script:
1. Checks Windows 10/11, PowerShell 5.1+
2. Installs Node.js (LTS) if not present
3. Installs Python 3 if not present (for ARGUS)
4. Installs all npm dependencies
5. Creates `.env` from `.env.example`
6. Builds Sentinel (TypeScript + Webpack)
7. Starts Sentinel

### Manual Installation / Manuelle Installation

**🇩🇪 Voraussetzungen / 🇬🇧 Prerequisites:**
- Windows 10/11 (64-bit)
- [Node.js 18+](https://nodejs.org/) (LTS)
- npm 9+
- 🇩🇪 Administrator-Rechte (für Firewall/Netzwerk) / 🇬🇧 Admin privileges (for firewall/network)
- [Python 3.10+](https://www.python.org/) (🇩🇪 für ARGUS AI, optional / 🇬🇧 for ARGUS AI, optional)

```bash
git clone https://github.com/YOUR_ALIAS/sentinel.git
cd sentinel
npm install

# Rebuild native modules for Electron / Native Module für Electron bauen
npx @electron/rebuild -f -w better-sqlite3

# Configure API keys (optional) / API-Keys konfigurieren (optional)
cp .env.example .env
# Edit .env — see docs/API_KEYS_GUIDE.md

npm run build
npm start
```

### ARGUS Backend (Optional)

```bash
cd ARGUS
pip install -r requirements.txt
python main.py
```

---

## Portability / Portabilität

🇬🇧 Sentinel uses **no hardcoded paths**. All configuration data is automatically stored
in the user data directory (`%APPDATA%\sentinel`).
The project can be cloned and run from any folder on any Windows machine.

🇩🇪 Sentinel verwendet **keine hardcodierten Pfade**. Alle Konfigurationsdaten werden
automatisch im Benutzerverzeichnis gespeichert (`%APPDATA%\sentinel`).
Das Projekt kann in jedem beliebigen Ordner geklont und ausgeführt werden.

---

## API Keys

🇬🇧 Sentinel works without API keys (reduced functionality).
See [API Keys Guide](docs/API_KEYS_GUIDE.md) for setup.

🇩🇪 Sentinel funktioniert ohne API-Keys (eingeschränkte Funktionalität).
Siehe [API Keys Guide](docs/API_KEYS_GUIDE.md).

| Key | 🇩🇪 Erforderlich / 🇬🇧 Required | Free Tier | 🇩🇪 Verwendet für / 🇬🇧 Used for |
|-----|--------------------------------|-----------|----------------------------------|
| ipinfo.io | Empfohlen / Recommended | 50k/month | IP-Geolokation / IP geolocation |
| VirusTotal | Optional | 500/day | URL/Datei-Scanning / URL/file scanning |
| AbuseIPDB | Optional | 1000/day | IP-Reputation / IP reputation |
| Shodan | Optional | Limited | Port-Erkennung / Port discovery |

---

## Privacy / Datenschutz (DSGVO / GDPR)

🇬🇧 Sentinel is GDPR-compliant (Art. 5, 6, 13, 17, 32 GDPR):

- **Local Processing** — All data stays on your device
- **Consent-gated Lookups** — External IP lookups (ipinfo.io) only when user explicitly enables them
- **Right to Erasure** — Activity log, threat events, and scan history deletable in Settings
- **Encryption** — Vault data encrypted with AES-256-GCM
- **No Telemetry** — Sentinel sends no usage data to third parties

🇩🇪 Sentinel ist DSGVO-konform (Art. 5, 6, 13, 17, 32 DSGVO):

- **Lokale Verarbeitung** — Alle Daten verbleiben auf dem Gerät
- **Einwilligungspflichtige Lookups** — Externe IP-Lookups (ipinfo.io) nur bei aktivierter Zustimmung
- **Recht auf Löschung** — Activity Log, Threat Events und Scan-Historie löschbar in Einstellungen
- **Verschlüsselung** — Vault-Daten mit AES-256-GCM verschlüsselt
- **Keine Telemetrie** — Sentinel sendet keine Nutzungsdaten an Dritte

---

## Architecture / Architektur

```
Electron Main Process ──→ IPC (Zod-validated) ──→ Renderer (React)
       │                                              │
       ├── PowerShell / WMI (system data)             ├── Dashboard
       ├── Firewall Engine (netsh/WFP)                ├── Network Monitor
       ├── Network Scanner                            ├── Firewall Page
       ├── Security Scanners (5 modules)              ├── Threat Intel
       ├── ARGUS Manager (Python backend)             ├── DNS & Privacy
       ├── Fix Safety System (undo/rollback)          ├── System Page
       └── Activity Logger                            ├── Vault
                                                      ├── Automation
                                                      └── Settings (i18n/GDPR)
```

## Security / Sicherheit

🇬🇧 English:
- All shell arguments sanitized with `sanitizeShellArg()` against command injection
- Scan fixes show detailed risk warnings before execution
- Dangerous fixes require explicit confirmation checkbox
- Automatic rollback if a fix breaks internet connectivity
- Protected process list prevents killing system-critical processes
- Context isolation + sandbox enabled, no nodeIntegration in renderer
- CSP enforced, all IPC messages validated with Zod schemas
- AES-256-GCM encryption for Vault data

🇩🇪 Deutsch:
- Alle Shell-Argumente mit `sanitizeShellArg()` gegen Injection geschützt
- Scan-Fixes zeigen Warnungen mit Risikobewertung vor der Ausführung
- Gefährliche Fixes erfordern explizite Bestätigung
- Automatisches Rollback wenn ein Fix die Internetverbindung unterbricht
- Geschützte Prozessliste verhindert das Beenden systemkritischer Prozesse
- Context Isolation + Sandbox aktiviert, kein nodeIntegration im Renderer
- CSP erzwungen, alle IPC-Nachrichten mit Zod-Schemas validiert
- AES-256-GCM-Verschlüsselung für Vault-Daten

## Contributing / Mitwirken

🇬🇧 English:
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open a Pull Request

🇩🇪 Deutsch:
1. Repository forken
2. Feature-Branch erstellen (`git checkout -b feature/amazing`)
3. Änderungen committen (`git commit -m 'Add amazing feature'`)
4. Branch pushen (`git push origin feature/amazing`)
5. Pull Request öffnen

See / Siehe [CONTRIBUTING.md](CONTRIBUTING.md) for details / für Details.

## License / Lizenz

MIT — see / siehe [LICENSE](LICENSE)
