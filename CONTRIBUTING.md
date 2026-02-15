# Contributing to Sentinel

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/sentinel.git`
3. Install dependencies: `npm install`
4. Create a feature branch: `git checkout -b feature/my-feature`

## Development

```bash
npm run build    # Build all 3 webpack configs (main, preload, renderer)
npm start        # Start Electron app
```

## Code Style

- **TypeScript** strict mode — avoid `any` where possible
- **IPC channels** — use constants from `src/shared/ipcChannels.ts`, not hardcoded strings
- **Error handling** — no empty catch blocks. Always `console.error` + user-facing notification
- **Activity logging** — call `addActivityLog()` for any action that modifies system state

## Security Rules

- Never expose API keys in code — use `envLoader.ts`
- All IPC inputs validated with Zod schemas in the Main process
- No `nodeIntegration` in renderer, all system access through preload bridge
- Scan fixes must go through the safety system (FixConfirmDialog + connectivity check)

## Pull Request Checklist

- [ ] `npm run build` passes with 0 errors
- [ ] No hardcoded API keys or personal data
- [ ] All new IPC handlers have activity logging
- [ ] All new buttons have loading states and error handling
- [ ] Scan fixes classified in `fixSafety.ts` with danger level + undo command
