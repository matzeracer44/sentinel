/**
 * SENTINEL UNIFIED — IPC Handler Registry
 * Single entry point to register all cluster IPC handlers.
 */

import { BrowserWindow } from 'electron';
import { registerFirewallHandlers, setFirewallContext } from './firewallHandlers';
import { registerIntelHandlers } from './intelHandlers';
import { registerNetworkHandlers } from './networkHandlers';
import { registerDnsHandlers, setDnsContext } from './dnsHandlers';
import { registerSystemHandlers, setSystemContext } from './systemHandlers';
import { registerVaultHandlers, setVaultContext } from './vaultHandlers';

export interface IPCRegistrationContext {
  mainWindow: BrowserWindow | null;
  isAdmin: boolean;
}

export function registerAllHandlers(ctx: IPCRegistrationContext): void {
  // Set context for handlers that need it
  setFirewallContext(ctx);
  setDnsContext(ctx);
  setSystemContext(ctx);
  setVaultContext(ctx);

  // Register all cluster handlers
  registerFirewallHandlers();
  registerIntelHandlers();
  registerNetworkHandlers();
  registerDnsHandlers();
  registerSystemHandlers();
  registerVaultHandlers();

  console.log('[IPC] All cluster handlers registered');
}

export function updateIPCContext(ctx: Partial<IPCRegistrationContext>): void {
  if (ctx.mainWindow !== undefined || ctx.isAdmin !== undefined) {
    setFirewallContext({ mainWindow: ctx.mainWindow ?? null, isAdmin: ctx.isAdmin ?? false });
    setDnsContext({ isAdmin: ctx.isAdmin ?? false });
    setSystemContext({ isAdmin: ctx.isAdmin ?? false });
    setVaultContext({ mainWindow: ctx.mainWindow ?? null });
  }
}
