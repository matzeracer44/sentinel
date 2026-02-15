# Mitwirken / Contributing to Sentinel

Vielen Dank für dein Interesse an Sentinel! Hier erfährst du, wie du zum Projekt beitragen kannst.
*Thank you for your interest in Sentinel! Here's how you can contribute to the project.*

---

## Erste Schritte / Getting Started

1. Repository forken / *Fork the repository*
2. Fork klonen / *Clone your fork:*
   ```bash
   git clone https://github.com/YOUR_USERNAME/sentinel.git
   ```
3. Abhängigkeiten installieren / *Install dependencies:*
   ```bash
   npm install
   npx @electron/rebuild -f -w better-sqlite3
   ```
4. Feature-Branch erstellen / *Create a feature branch:*
   ```bash
   git checkout -b feature/mein-feature
   ```

---

## Entwicklung / Development

```bash
npm run build    # Alle 3 Webpack-Configs bauen (Main, Preload, Renderer)
                 # Build all 3 webpack configs (main, preload, renderer)

npm start        # Electron-App starten / Start Electron app

npm run dev      # Build + Start in einem Schritt / Build + Start in one step
```

### Projektstruktur / Project Structure

```
src/
├── main/           # Electron Hauptprozess / Main process
│   ├── ipc/        # IPC-Handler (Zod-validiert / Zod-validated)
│   ├── services/   # System-Services (PowerShell, Netzwerk, Sicherheit)
│   └── main.ts     # Haupteinstiegspunkt / Main entry point
├── preload/        # Preload-Bridge (contextIsolation)
├── renderer/       # React-Frontend
│   ├── components/ # Wiederverwendbare Komponenten / Reusable components
│   ├── pages/      # 9 Hauptseiten / 9 main pages
│   └── i18n/       # Übersetzungen (en.ts, de.ts) / Translations
└── shared/         # Geteilte Typen & Utils (Main + Renderer)
    ├── utils.ts    # sanitizeShellArg, IP-Validierung, Formatierung
    ├── fixSafety.ts # Fix-Klassifizierungen & Verbotsliste
    └── constants.ts # Prozess-Schutzlisten / Process protection lists
```

---

## Code-Stil / Code Style

- **TypeScript** strict mode — vermeide `any` wo möglich / *avoid `any` where possible*
- **Shell-Befehle** — IMMER `sanitizeShellArg()` für Benutzereingaben verwenden, die an `execSync` gehen
  *Always use `sanitizeShellArg()` for user input going into execSync*
- **Fehlerbehandlung** — keine leeren Catch-Blöcke. Immer `console.warn('[Modul]', e?.message)` + `notify.error()`
  *No empty catch blocks. Always console.warn + notify.error*
- **Aktivitätsprotokoll** — `addActivityLog()` für jede Aktion aufrufen, die den Systemzustand ändert
  *Call addActivityLog() for any action that modifies system state*
- **Lokalisierung** — neue UI-Texte als Key in `en.ts` und `de.ts` hinzufügen, `t('key')` im JSX verwenden
  *Add new UI text as keys in en.ts and de.ts, use t('key') in JSX*
- **Locale-sicher** — PowerShell-Ausgaben niemals gegen englische Strings prüfen (z.B. "Running", "Enabled").
  Verwende numerische Werte oder strukturierte Objekte.
  *Never match PowerShell output against English strings. Use numeric values or structured objects.*

---

## Sicherheitsregeln / Security Rules

- **Keine API-Keys im Code** — verwende `envLoader.ts` / *use envLoader.ts*
- **Alle IPC-Eingaben** mit Zod-Schemas im Main-Prozess validieren / *validate with Zod schemas in Main process*
- **Kein `nodeIntegration`** im Renderer — aller Systemzugriff über Preload-Bridge
  *No nodeIntegration in renderer — all system access through preload bridge*
- **Shell-Injection** — `sanitizeShellArg()` für JEDEN String verwenden, der in Shell-Befehle interpoliert wird
  *Use sanitizeShellArg() for EVERY string interpolated into shell commands*
- **Scan-Fixes** müssen durch das Sicherheitssystem (FixConfirmDialog + Konnektivitätsprüfung)
  *Scan fixes must go through the safety system (FixConfirmDialog + connectivity check)*
- **DSGVO** — keine PII in Logs, keine externen Aufrufe ohne Einwilligung
  *No PII in logs, no external calls without consent*

---

## Übersetzungen / Translations

Sentinel unterstützt Deutsch und Englisch. Beim Hinzufügen neuer UI-Texte:
*Sentinel supports German and English. When adding new UI text:*

1. Key in `src/renderer/i18n/en.ts` hinzufügen / *Add key to en.ts*
2. Gleichen Key in `src/renderer/i18n/de.ts` mit deutscher Übersetzung / *Same key in de.ts with German translation*
3. `useTranslation()` Hook im Komponent verwenden / *Use useTranslation() hook in component*
4. `t('your.key')` im JSX verwenden / *Use t('your.key') in JSX*

---

## Pull-Request-Checkliste / Pull Request Checklist

- [ ] `npm run build` läuft ohne Fehler / *passes with 0 errors*
- [ ] Keine hardcodierten API-Keys oder persönliche Daten / *No hardcoded API keys or personal data*
- [ ] Keine hardcodierten Pfade (verwende `app.getPath()`) / *No hardcoded paths (use app.getPath())*
- [ ] Alle neuen IPC-Handler haben Aktivitätsprotokollierung / *All new IPC handlers have activity logging*
- [ ] Alle neuen Buttons haben Ladezustände und Fehlerbehandlung / *All new buttons have loading states and error handling*
- [ ] Shell-Befehle mit `sanitizeShellArg()` abgesichert / *Shell commands secured with sanitizeShellArg()*
- [ ] Scan-Fixes in `fixSafety.ts` klassifiziert mit Gefahrenstufe + Undo-Befehl
  *Scan fixes classified in fixSafety.ts with danger level + undo command*
- [ ] Neue UI-Texte in `en.ts` und `de.ts` übersetzt / *New UI text translated in en.ts and de.ts*
- [ ] PowerShell-Befehle funktionieren auf deutschem UND englischem Windows
  *PowerShell commands work on German AND English Windows*

---

## Lizenz / License

Mit dem Einreichen eines Pull Requests stimmst du zu, dass dein Beitrag unter der MIT-Lizenz veröffentlicht wird.
*By submitting a pull request, you agree that your contribution will be released under the MIT License.*
