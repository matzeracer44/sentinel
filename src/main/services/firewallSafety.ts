// Firewall service with safety checks, internet testing, and undo/redo
import { addActivityLog } from './activityLog';
import { loadFirewallStacks, persistFirewallStacks } from './firewallHistoryStore';
import { performConnectivityCheck, type ConnectivityResult } from './connectivityCheck';
import { addSentinelRule } from './shieldData';

export interface FirewallAction {
  id: string;
  type: 'block-port' | 'block-subnet' | 'block-ip' | 'block-program';
  timestamp: number;
  details: any;
}

interface BlockPortOptions {
  loopbackOnly?: boolean;
}

/**
 * Block every connection for the executable backing a PID using program-based firewall rules
 */
export async function blockProcessByPid(
  pid: number,
  direction: 'in' | 'out' | 'both' = 'both'
): Promise<{ success: boolean; message: string }> {
  if (!Number.isFinite(pid) || pid < 0) {
    return { success: false, message: 'Invalid PID (must be a non-negative integer)' };
  }

  const { execSync } = require('child_process');
  const isSystemPid = pid === 0;

  const resolveProcessPath = (): string | null => {
    try {
      const psCommand =
        `powershell -ExecutionPolicy Bypass -NoProfile -Command "` +
        `(Get-Process -Id ${pid} -ErrorAction Stop | Select-Object -First 1 -Property Path).Path"`;
      const output = execSync(psCommand, {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      }).trim();
      if (output) return output;
    } catch {}

    try {
      const wmicOutput = execSync(`wmic process where processid=${pid} get ExecutablePath /value`, {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
      });
      const match = wmicOutput.match(/ExecutablePath=(.*)/i);
      if (match && match[1]) {
        const path = match[1].trim();
        if (path) return path;
      }
    } catch {}

    return null;
  };

  const processPath = isSystemPid ? null : resolveProcessPath();
  if (!isSystemPid && !processPath) {
    return { success: false, message: `Unable to resolve executable for PID ${pid}` };
  }

  try {
    const ruleBase = `Sentinel Block PID ${pid}`;
    const directions = direction === 'both' ? ['in', 'out'] : [direction];
    const ruleNames: string[] = [];

    for (const dir of directions) {
      const suffix = direction === 'both' ? (dir === 'in' ? ' IN' : ' OUT') : '';
      const ruleName = `${ruleBase}${suffix}`;
      const command = isSystemPid
        ? `netsh advfirewall firewall add rule name="${ruleName}" dir=${dir} action=block service=system enable=yes`
        : `netsh advfirewall firewall add rule name="${ruleName}" dir=${dir} action=block program="${processPath}" enable=yes`;
      execSync(command, { windowsHide: true });
      ruleNames.push(ruleName);
    }

    const action: FirewallAction = {
      id: `block-program-${pid}-${Date.now()}`,
      type: 'block-program',
      timestamp: Date.now(),
      details: {
        pid,
        processPath,
        direction,
        service: isSystemPid ? 'system' : undefined,
        ruleNames,
      },
    };

    undoStack.push(action);
    redoStack = [];
    await persistStacks();

    const targetDescriptor = isSystemPid ? 'System (PID 0)' : `${pid} (${processPath})`;
    addActivityLog('Shield', 'Block PID', `Blocked ${targetDescriptor}`, 'success');

    return { success: true, message: `PID ${pid} (${direction}) blocked successfully` };
  } catch (error: any) {
    addActivityLog('Shield', 'Block PID', `Error: ${error.message}`, 'error');
    return { success: false, message: `Error: ${error.message}` };
  }
}

// In-memory undo/redo stacks
let undoStack: FirewallAction[] = [];
let redoStack: FirewallAction[] = [];

export async function hydrateFirewallHistoryStacks(): Promise<void> {
  try {
    const stacks = await loadFirewallStacks();
    undoStack = Array.isArray(stacks.undo) ? stacks.undo : [];
    redoStack = Array.isArray(stacks.redo) ? stacks.redo : [];
    addActivityLog('Shield', 'Firewall History', `Hydrated ${undoStack.length} undo / ${redoStack.length} redo actions`, 'info');
  } catch (err: any) {
    console.warn('[FirewallSafety] Failed to hydrate firewall history stacks:', err?.message || err);
    undoStack = [];
    redoStack = [];
  }
}

async function persistStacks(): Promise<void> {
  try {
    await persistFirewallStacks({ undo: undoStack, redo: redoStack });
  } catch (err: any) {
    console.warn('[FirewallSafety] Failed to persist firewall stacks:', err?.message || err);
  }
}

const CRITICAL_PORTS = [53, 80, 443, 8080]; // DNS, HTTP, HTTPS, HTTP-Alt

/**
 * Test internet connectivity via async DNS + HTTP probe (cached)
 */
export async function testInternet(): Promise<boolean> {
  try {
    const result = await performConnectivityCheck();
    return result.connected;
  } catch (err) {
    console.warn('[FirewallSafety] Connectivity check failed:', err);
    return false;
  }
}

export async function getConnectivityStatus(options: { force?: boolean } = {}): Promise<ConnectivityResult> {
  return performConnectivityCheck(options);
}

/**
 * Block a port with safety checks
 */
export async function safeBlockPort(
  port: number,
  direction: 'in' | 'out' | 'both' = 'both',
  protocol: 'TCP' | 'UDP' | 'Both' = 'TCP',
  options: BlockPortOptions = {}
): Promise<{ success: boolean; message: string; rollback?: boolean }> {
  // Validate port
  if (port < 0 || port > 65535) {
    return { success: false, message: 'Invalid port number (0-65535)' };
  }

  // Critical port warning
  if (CRITICAL_PORTS.includes(port)) {
    return {
      success: false,
      message: `WARNING: Blocking port ${port} may break internet connectivity. Please confirm explicitly.`,
    };
  }

  try {
    const loopbackOnly = Boolean(options.loopbackOnly);
    const remoteConstraint = loopbackOnly ? ' remoteip=127.0.0.1,::1' : '';
    const loopbackLabel = loopbackOnly ? ' (loopback only)' : '';
    const createdRuleNames: string[] = [];

    // 1. Test internet BEFORE
    const internetBefore = await testInternet();
    if (!internetBefore) {
      addActivityLog('Shield', 'Block Port', `Internet already down, skipping internet test`, 'warning');
    }

    // 2. Create firewall rule
    const ruleName = `Sentinel Block Port ${port}/${protocol}`;

    const { execSync } = require('child_process');
    if (direction === 'both') {
      // Create both IN and OUT rules
      const inboundName = `${ruleName} IN`;
      execSync(
        `netsh advfirewall firewall add rule name="${inboundName}" dir=in action=block protocol=${protocol} localport=${port}${remoteConstraint} enable=yes`,
        { windowsHide: true }
      );
      createdRuleNames.push(inboundName);
      const outboundName = `${ruleName} OUT`;
      execSync(
        `netsh advfirewall firewall add rule name="${outboundName}" dir=out action=block protocol=${protocol} localport=${port}${remoteConstraint} enable=yes`,
        { windowsHide: true }
      );
      createdRuleNames.push(outboundName);
    } else {
      execSync(
        `netsh advfirewall firewall add rule name="${ruleName}" dir=${direction === 'in' ? 'in' : 'out'} action=block protocol=${protocol} localport=${port}${remoteConstraint} enable=yes`,
        { windowsHide: true }
      );
      createdRuleNames.push(ruleName);
    }

    // 3. Wait for rule to apply
    await new Promise((r) => setTimeout(r, 2000));

    // 4. Test internet AFTER
    const internetAfter = await testInternet();

    // 5. Rollback if internet broken
    if (internetBefore && !internetAfter) {
      if (direction === 'both') {
        execSync(`netsh advfirewall firewall delete rule name="${ruleName} IN" dir=in`, {
          windowsHide: true,
        });
        execSync(`netsh advfirewall firewall delete rule name="${ruleName} OUT" dir=out`, {
          windowsHide: true,
        });
      } else {
        execSync(`netsh advfirewall firewall delete rule name="${ruleName}"`, {
          windowsHide: true,
        });
      }

      addActivityLog(
        'Shield',
        'Block Port',
        `Rollback: Blocking port ${port} broke internet, rule deleted`,
        'error'
      );

      return {
        success: false,
        message: `Block would break internet. Rolled back.`,
        rollback: true,
      };
    }

    // 6a. Track created firewall rules for orchestrator visibility
    createdRuleNames.forEach((name) => addSentinelRule(name));

    // 6. Success - add to undo stack
    const action: FirewallAction = {
      id: `block-port-${port}-${Date.now()}`,
      type: 'block-port',
      timestamp: Date.now(),
      details: { port, direction, protocol, ruleName, loopbackOnly },
    };
    undoStack.push(action);
    redoStack = []; // Clear redo stack
    await persistStacks();

    addActivityLog(
      'Shield',
      'Block Port',
      `Port ${port}/${protocol} blocked (${direction})${loopbackLabel}`,
      'success'
    );

    return { success: true, message: `Port ${port} blocked successfully${loopbackLabel}` };
  } catch (error: any) {
    addActivityLog('Shield', 'Block Port', `Error: ${error.message}`, 'error');
    return { success: false, message: `Error: ${error.message}` };
  }
}

/**
 * Check if IP is in private network range
 */
function isPrivateNetwork(ip: string): boolean {
  const octets = ip.split('.').map(Number);
  if (octets.length !== 4) return false;
  
  // 10.0.0.0/8
  if (octets[0] === 10) return true;
  // 172.16.0.0/12
  if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) return true;
  // 192.168.0.0/16
  if (octets[0] === 192 && octets[1] === 168) return true;
  // 127.0.0.0/8 (localhost)
  if (octets[0] === 127) return true;
  
  return false;
}

/**
 * Parse CIDR notation or IP with mask
 */
function parseCIDR(input: string): { ip: string; mask: number } | null {
  // Check if input is in CIDR notation (e.g., "192.168.1.0/24")
  const cidrMatch = input.match(/^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/(\d{1,2})$/);
  if (cidrMatch) {
    const ip = cidrMatch[1];
    const mask = parseInt(cidrMatch[2], 10);
    if (mask >= 0 && mask <= 32) {
      return { ip, mask };
    }
  }
  return null;
}

/**
 * Block IP subnet with validation and enhanced features
 */
export async function blockSubnet(
  input: string,
  subnetMask?: 8 | 16 | 20 | 22 | 24 | 26 | 30 | 32,
  direction: 'in' | 'out' | 'both' = 'both'
): Promise<{ success: boolean; message: string; preview?: string; warning?: string }> {
  try {
    let ip: string;
    let mask: number;

    // Try to parse CIDR notation first
    const cidr = parseCIDR(input);
    if (cidr) {
      ip = cidr.ip;
      mask = cidr.mask;
    } else {
      // Fallback to IP + separate mask
      ip = input;
      mask = subnetMask || 32;
    }

    // Validate IP
    const ipRegex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
    const match = ip.match(ipRegex);
    if (!match) {
      return { success: false, message: 'Invalid IP address format' };
    }

    const octets = match.slice(1).map(Number);
    if (octets.some((o) => o > 255)) {
      return { success: false, message: 'Invalid IP address (octets must be 0-255)' };
    }

    // Check for private network
    const isPrivate = isPrivateNetwork(ip);
    let warning: string | undefined;
    if (isPrivate) {
      warning = `⚠️ WARNING: ${ip} is in a private network range. Blocking this may affect local network connectivity.`;
    }

    // Calculate subnet based on mask
    let subnet = '';
    const affectedIPs = Math.pow(2, 32 - mask);
    
    if (mask === 32) {
      subnet = ip;
    } else if (mask === 24) {
      subnet = `${octets[0]}.${octets[1]}.${octets[2]}.0/24`;
    } else if (mask === 16) {
      subnet = `${octets[0]}.${octets[1]}.0.0/16`;
    } else if (mask === 8) {
      subnet = `${octets[0]}.0.0.0/8`;
    } else {
      // For custom masks, calculate the network address
      const ipInt = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3];
      const maskInt = (0xFFFFFFFF << (32 - mask)) >>> 0;
      const networkInt = (ipInt & maskInt) >>> 0;
      
      const netOctets = [
        (networkInt >>> 24) & 0xFF,
        (networkInt >>> 16) & 0xFF,
        (networkInt >>> 8) & 0xFF,
        networkInt & 0xFF
      ];
      
      subnet = `${netOctets.join('.')}/${mask}`;
    }

    const preview = `Blocking ${subnet} (affects ${affectedIPs.toLocaleString()} IP${affectedIPs > 1 ? 's' : ''})`;

    // Test internet BEFORE blocking (if not private network)
    const internetBefore = await testInternet();
    if (!internetBefore && !isPrivate) {
      addActivityLog('Shield', 'Block Subnet', 'Internet already down, skipping safety test', 'warning');
    }

    // Create firewall rules
    const { execSync } = require('child_process');
    const ruleName = `Sentinel Block Subnet ${subnet}`;

    if (direction === 'both') {
      execSync(
        `netsh advfirewall firewall add rule name="${ruleName} IN" dir=in action=block remoteip=${subnet} enable=yes`,
        { windowsHide: true }
      );
      execSync(
        `netsh advfirewall firewall add rule name="${ruleName} OUT" dir=out action=block remoteip=${subnet} enable=yes`,
        { windowsHide: true }
      );
    } else {
      execSync(
        `netsh advfirewall firewall add rule name="${ruleName}" dir=${direction === 'in' ? 'in' : 'out'} action=block remoteip=${subnet} enable=yes`,
        { windowsHide: true }
      );
    }

    // Wait for rule to apply
    await new Promise((r) => setTimeout(r, 1500));

    // Test internet AFTER blocking (if not private network)
    if (internetBefore && !isPrivate) {
      const internetAfter = await testInternet();
      if (!internetAfter) {
        // Rollback
        if (direction === 'both') {
          try {
            execSync(`netsh advfirewall firewall delete rule name="${ruleName} IN" dir=in`, { windowsHide: true });
          } catch {}
          try {
            execSync(`netsh advfirewall firewall delete rule name="${ruleName} OUT" dir=out`, { windowsHide: true });
          } catch {}
        } else {
          try {
            execSync(`netsh advfirewall firewall delete rule name="${ruleName}"`, { windowsHide: true });
          } catch {}
        }

        addActivityLog('Shield', 'Block Subnet', `Rollback: Blocking ${subnet} broke internet connectivity`, 'error');
        return {
          success: false,
          message: `Blocking ${subnet} would break internet connectivity. Rule rolled back.`,
        };
      }
    }

    // Add to undo stack
    const action: FirewallAction = {
      id: `block-subnet-${subnet}-${Date.now()}`,
      type: 'block-subnet',
      timestamp: Date.now(),
      details: { subnet, direction, ruleName },
    };
    undoStack.push(action);
    redoStack = [];

    addActivityLog('Shield', 'Block Subnet', `Subnet ${subnet} blocked (${direction})`, 'success');

    return { success: true, message: `${subnet} blocked successfully`, preview, warning };
  } catch (error: any) {
    addActivityLog('Shield', 'Block Subnet', `Error: ${error.message}`, 'error');
    return { success: false, message: `Error: ${error.message}` };
  }
}

/**
 * Undo last firewall action
 */
export async function undoFirewallAction(): Promise<{ success: boolean; message: string }> {
  if (undoStack.length === 0) {
    return { success: false, message: 'Nothing to undo' };
  }

  try {
    const action = undoStack.pop()!;
    redoStack.push(action);
    await persistStacks();

    const { execSync } = require('child_process');

    if (action.type === 'block-port') {
      const { ruleName } = action.details;
      try {
        execSync(`netsh advfirewall firewall delete rule name="${ruleName} IN" dir=in`, {
          windowsHide: true,
        });
      } catch {}
      try {
        execSync(`netsh advfirewall firewall delete rule name="${ruleName} OUT" dir=out`, {
          windowsHide: true,
        });
      } catch {}
      try {
        execSync(`netsh advfirewall firewall delete rule name="${ruleName}"`, {
          windowsHide: true,
        });
      } catch {}
    } else if (action.type === 'block-subnet') {
      const { ruleName } = action.details;
      try {
        execSync(`netsh advfirewall firewall delete rule name="${ruleName} IN" dir=in`, {
          windowsHide: true,
        });
      } catch {}
      try {
        execSync(`netsh advfirewall firewall delete rule name="${ruleName} OUT" dir=out`, {
          windowsHide: true,
        });
      } catch {}
      try {
        execSync(`netsh advfirewall firewall delete rule name="${ruleName}"`, {
          windowsHide: true,
        });
      } catch {}
    } else if (action.type === 'block-program') {
      const { ruleNames } = action.details;
      for (const name of ruleNames || []) {
        try {
          execSync(`netsh advfirewall firewall delete rule name="${name}"`, { windowsHide: true });
        } catch {}
      }
    }

    addActivityLog('Shield', 'Undo', `Undid: ${action.type}`, 'success');
    return { success: true, message: 'Action undone' };
  } catch (error: any) {
    return { success: false, message: `Error: ${error.message}` };
  }
}

/**
 * Redo last undone firewall action
 */
export async function redoFirewallAction(): Promise<{ success: boolean; message: string }> {
  if (redoStack.length === 0) {
    return { success: false, message: 'Nothing to redo' };
  }

  try {
    const action = redoStack.pop()!;
    undoStack.push(action);
    await persistStacks();

    const { execSync } = require('child_process');

    if (action.type === 'block-port') {
      const { port, protocol, direction, ruleName, loopbackOnly } = action.details;
      const remoteConstraint = loopbackOnly ? ' remoteip=127.0.0.1,::1' : '';
      if (direction === 'both') {
        execSync(
          `netsh advfirewall firewall add rule name="${ruleName} IN" dir=in action=block protocol=${protocol} localport=${port}${remoteConstraint} enable=yes`,
          { windowsHide: true }
        );
        execSync(
          `netsh advfirewall firewall add rule name="${ruleName} OUT" dir=out action=block protocol=${protocol} localport=${port}${remoteConstraint} enable=yes`,
          { windowsHide: true }
        );
      } else {
        execSync(
          `netsh advfirewall firewall add rule name="${ruleName}" dir=${direction === 'in' ? 'in' : 'out'} action=block protocol=${protocol} localport=${port}${remoteConstraint} enable=yes`,
          { windowsHide: true }
        );
      }
    } else if (action.type === 'block-subnet') {
      const { subnet, direction, ruleName } = action.details;
      if (direction === 'both') {
        execSync(
          `netsh advfirewall firewall add rule name="${ruleName} IN" dir=in action=block remoteip=${subnet} enable=yes`,
          { windowsHide: true }
        );
        execSync(
          `netsh advfirewall firewall add rule name="${ruleName} OUT" dir=out action=block remoteip=${subnet} enable=yes`,
          { windowsHide: true }
        );
      } else {
        execSync(
          `netsh advfirewall firewall add rule name="${ruleName}" dir=${direction === 'in' ? 'in' : 'out'} action=block remoteip=${subnet} enable=yes`,
          { windowsHide: true }
        );
      }
    } else if (action.type === 'block-program') {
      const { processPath, direction, ruleNames = [], service } = action.details;
      const directions = direction === 'both' ? ['in', 'out'] : [direction];
      directions.forEach((dir: 'in' | 'out', idx: number) => {
        const ruleName = ruleNames[idx] || `${action.id}-${dir}`;
        const command = service === 'system'
          ? `netsh advfirewall firewall add rule name="${ruleName}" dir=${dir} action=block service=system enable=yes`
          : `netsh advfirewall firewall add rule name="${ruleName}" dir=${dir} action=block program="${processPath}" enable=yes`;
        execSync(command, { windowsHide: true });
      });
    }

    addActivityLog('Shield', 'Redo', `Redid: ${action.type}`, 'success');
    return { success: true, message: 'Action redone' };
  } catch (error: any) {
    return { success: false, message: `Error: ${error.message}` };
  }
}

/**
 * Get undo/redo stack status
 */
export function getUndoRedoStatus() {
  return {
    canUndo: undoStack.length > 0,
    canRedo: redoStack.length > 0,
    undoCount: undoStack.length,
    redoCount: redoStack.length,
  };
}
