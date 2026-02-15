<div align="center">
  <h1>SENTINEL</h1>
  <p><strong>Unified Security Suite for Windows</strong></p>
  <p>Real-time threat monitoring, network analysis, firewall management,
  privacy hardening, and system security — all in one desktop app.</p>

  <img src="https://img.shields.io/badge/Platform-Windows%2011-blue" />
  <img src="https://img.shields.io/badge/Electron-28-green" />
  <img src="https://img.shields.io/badge/TypeScript-5-blue" />
  <img src="https://img.shields.io/badge/React-18-cyan" />
  <img src="https://img.shields.io/badge/License-MIT-yellow" />
</div>

---

## Features

- **Shield / Firewall Engine** — Real-time rule management, IP/port/subnet blocking, undo/redo
- **Network Monitor** — Live connections, TLS inspection, process tracking, beaconing detection
- **ARGUS AI Sandbox** — URL scanning, threat classification, behavioral analysis
- **Threat Intelligence** — Guardian stories, anomaly detection, automated playbooks
- **Vault** — AES-256-GCM encryption, secure notes, password generator, file shredder
- **Ghost / DNS & Privacy** — DNS configuration, hosts management, telemetry control
- **Forge / System Monitor** — Hardware diagnostics, performance tuning, health scoring
- **Security Scans** — 100+ checks across 5 modules (Network, EDR, Kernel, Privacy, Performance)

## Quick Start

### Prerequisites
- Windows 10/11 (64-bit)
- Node.js 18+ (LTS recommended)
- npm 9+
- Administrator privileges (for firewall/network features)
- Python 3.10+ (for ARGUS AI, optional)

### Installation

```bash
git clone https://github.com/YOUR_ALIAS/sentinel.git
cd sentinel
npm install

# Configure API keys (optional but recommended)
cp .env.example .env
# Edit .env with your API keys — see docs/API_KEYS_GUIDE.md

npm run build
npm start
```

### ARGUS Setup (Optional)

```bash
cd ARGUS
pip install -r requirements.txt
python main.py
```

## API Keys

Sentinel works without API keys (reduced functionality).
See [API Keys Guide](docs/API_KEYS_GUIDE.md) for setup.

| Key | Required | Free Tier | Used For |
|-----|----------|-----------|----------|
| ipinfo.io | Recommended | 50k/month | IP geolocation |
| VirusTotal | Optional | 500/day | URL/file scanning |
| AbuseIPDB | Optional | 1000/day | IP reputation |
| Shodan | Optional | Limited | Port discovery |

## Architecture

```
Electron Main Process ──→ IPC ──→ Renderer (React)
       │                              │
       ├── PowerShell (system data)   ├── Dashboard
       ├── Firewall Engine            ├── Network Monitor
       ├── Network Scanner            ├── Firewall Page
       ├── Security Scanners          ├── Threat Intel
       ├── ARGUS Manager              ├── DNS & Privacy
       └── Activity Logger            ├── System Page
                                      ├── Vault
                                      └── Automation
```

## Security

- All scan fixes show detailed warnings before execution
- Dangerous fixes require explicit confirmation checkbox
- Automatic rollback if a fix breaks internet connectivity
- Protected process list prevents killing system-critical processes
- Activity log tracks all security-relevant actions
- Context isolation + sandbox enabled, no nodeIntegration in renderer
- CSP enforced, all IPC messages validated with Zod schemas
- AES-256-GCM encryption for Vault data

## Contributing

1. Fork the repo
2. Create feature branch (`git checkout -b feature/amazing`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing`)
5. Open Pull Request

## License

MIT — see [LICENSE](LICENSE)
