/**
 * SENTINEL — Network & WFP Advanced Module
 * 15 network security checks: WFP, DoH, TCP hardening, ARP, SMB, stealth, etc.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
const execFileAsync = promisify(execFile);

export interface NetCheck {
  id: string;
  name: string;
  status: 'pass' | 'fail' | 'warn' | 'unknown';
  detail: string;
  risk: 'low' | 'medium' | 'high' | 'critical';
  offenders?: { label: string; detail: string; severity?: string }[];
}

async function ps(script: string, timeout = 12000): Promise<string> {
  const encoded = Buffer.from(script, 'utf16le').toString('base64');
  const { stdout } = await execFileAsync('powershell.exe',
    ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', encoded],
    { timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }
  );
  return (stdout || '').trim();
}

async function safe(id: string, name: string, fn: () => Promise<NetCheck>): Promise<NetCheck> {
  try { return await fn(); } catch (e: any) { return { id, name, status: 'unknown', detail: e.message, risk: 'medium' }; }
}

export async function checkWFP(): Promise<NetCheck> {
  return safe('net-wfp', 'WFP Kernel-Filter', async () => {
    const out = await ps(`$b=(Get-Service BFE -EA SilentlyContinue).Status;$m=(Get-Service MpsSvc -EA SilentlyContinue).Status;$p=(Get-NetFirewallProfile|?{$_.Enabled}).Count;"BFE:$b|MpsSvc:$m|Profiles:$p/3"`);
    const ok = out.includes('BFE:Running') && out.includes('Profiles:3/3');
    return { id: 'net-wfp', name: 'WFP Kernel-Filter', status: ok ? 'pass' : 'fail', detail: out, risk: ok ? 'low' : 'critical' };
  });
}

export async function checkGeoIP(): Promise<NetCheck> {
  return safe('net-geoip', 'Geo-IP Blocking', async () => {
    const out = await ps(`$r=Get-NetFirewallRule -DisplayName '*GeoBlock*','*Sentinel*Block*' -EA SilentlyContinue;$c=if($r){($r|Measure).Count}else{0};"Rules:$c"`);
    const m = out.match(/Rules:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'net-geoip', name: 'Geo-IP Blocking', status: c > 0 ? 'pass' : 'warn', detail: `${c} geo-block rules active`, risk: c > 0 ? 'low' : 'medium' };
  });
}

export async function checkDoH(): Promise<NetCheck> {
  return safe('net-doh', 'DNS-over-HTTPS', async () => {
    const out = await ps(`$doh=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' -EA SilentlyContinue).EnableAutoDoh;$dns=Get-DnsClientServerAddress -AddressFamily IPv4|?{$_.ServerAddresses.Count-gt0}|Select -First 1 -Expand ServerAddresses;$k=@('1.1.1.1','8.8.8.8','9.9.9.9');$cap=$false;foreach($s in $dns){if($k-contains$s){$cap=$true}};"AutoDoH:$doh|DNS:$($dns-join',')|DoHCapable:$cap"`);
    const cap = out.includes('DoHCapable:True');
    return { id: 'net-doh', name: 'DNS-over-HTTPS', status: cap ? 'pass' : 'warn', detail: out, risk: cap ? 'low' : 'medium' };
  });
}

export async function checkTCPHardening(): Promise<NetCheck> {
  return safe('net-tcphard', 'TCP Stack Hardening', async () => {
    const out = await ps(`$t=Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -EA SilentlyContinue;"SynProtect:$($t.SynAttackProtect)|DeadGW:$($t.EnableDeadGWDetect)|PMTU:$($t.EnablePMTUDiscovery)"`);
    const synProtect = out.includes('SynProtect:1');
    return { id: 'net-tcphard', name: 'TCP Stack Hardening', status: synProtect ? 'pass' : 'warn', detail: out, risk: synProtect ? 'low' : 'medium' };
  });
}

export async function checkOutboundControl(): Promise<NetCheck> {
  return safe('net-outbound', 'Process Outbound Control', async () => {
    const out = await ps(`$b=(Get-NetFirewallProfile|?{$_.DefaultOutboundAction-eq'Block'}).Count;"OutboundBlockProfiles:$b/3"`);
    const m = out.match(/OutboundBlockProfiles:(\d+)/);
    const c = m ? parseInt(m[1]) : 0;
    return { id: 'net-outbound', name: 'Process Outbound Control', status: c >= 1 ? 'pass' : 'warn', detail: out, risk: c >= 1 ? 'low' : 'medium' };
  });
}

export async function checkTorBlocking(): Promise<NetCheck> {
  return safe('net-torblock', 'Tor/Proxy Blocking', async () => {
    const out = await ps(`$r=Get-NetFirewallRule -DisplayName '*Tor*','*Proxy*Block*' -EA SilentlyContinue;$c=if($r){($r|Measure).Count}else{0};"Rules:$c"`);
    const rm = out.match(/Rules:(\d+)/);
    const rc = rm ? parseInt(rm[1]) : 0;
    return { id: 'net-torblock', name: 'Tor/Proxy Blocking', status: rc > 0 ? 'pass' : 'warn', detail: `${rc} Tor/Proxy block rules active`, risk: rc > 0 ? 'low' : 'medium' };
  });
}

export async function checkPortStealth(): Promise<NetCheck> {
  return safe('net-stealth', 'Port Stealthing', async () => {
    const out = await ps(`$i=Get-NetFirewallRule -DisplayName '*ICMPv4*' -EA SilentlyContinue|?{$_.Action-eq'Block'-and$_.Enabled-eq'True'};if($i){'STEALTHED'}else{'VISIBLE'}`);
    const ok = out.includes('STEALTHED');
    return { id: 'net-stealth', name: 'Port Stealthing', status: ok ? 'pass' : 'warn', detail: ok ? 'ICMP blocked — ports stealthed' : 'ICMP not blocked — system visible to scanners', risk: ok ? 'low' : 'medium' };
  });
}

export async function checkARPProtection(): Promise<NetCheck> {
  return safe('net-arp', 'ARP Spoofing Protection', async () => {
    const script = `$ErrorActionPreference='SilentlyContinue'
$arp = Get-NetNeighbor -AddressFamily IPv4 -EA SilentlyContinue | Where-Object { $_.IPAddress -ne '255.255.255.255' -and $_.IPAddress -ne '224.0.0.22' }
$results = @()
foreach ($e in ($arp | Select-Object -First 20)) {
  $results += [PSCustomObject]@{ ip=$e.IPAddress; mac=$e.LinkLayerAddress; state=$e.State.ToString(); iface=$e.InterfaceAlias }
}
$d = ($arp | Where-Object { $_.State -eq 'Reachable' -or $_.State -eq 'Stale' }).Count
$s = ($arp | Where-Object { $_.State -eq 'Permanent' }).Count
@{ entries=$results; dynamic=[int]$d; static=[int]$s } | ConvertTo-Json -Depth 2 -Compress`;
    const raw = await ps(script, 8000);
    let dynamic = 0, staticCount = 0;
    let offenders: { label: string; detail: string; severity?: string }[] = [];
    try {
      const parsed = JSON.parse(raw || '{}');
      dynamic = parsed.dynamic || 0;
      staticCount = parsed.static || 0;
      const entries = Array.isArray(parsed.entries) ? parsed.entries : parsed.entries ? [parsed.entries] : [];
      offenders = entries.map((e: any) => ({
        label: `${e.ip} → ${e.mac || 'N/A'}`,
        detail: `${e.state || 'Unknown'} on ${e.iface || 'N/A'}`,
        severity: e.state === 'Permanent' ? 'LOW' : 'MEDIUM',
      }));
    } catch { /* fallback */ }
    const detail = `Dynamic: ${dynamic} | Static: ${staticCount}${staticCount === 0 ? ' — gateway unprotected from ARP spoofing' : ''}`;
    return { id: 'net-arp', name: 'ARP Table Status', status: staticCount > 0 ? 'pass' : 'warn', detail, risk: staticCount > 0 ? 'low' : 'medium', offenders };
  });
}

export async function checkDomainReputation(): Promise<NetCheck> {
  return safe('net-domrep', 'Domain Reputation Filter', async () => {
    const out = await ps(`$np=(Get-MpPreference -EA SilentlyContinue).EnableNetworkProtection;$pua=(Get-MpPreference -EA SilentlyContinue).PUAProtection;"NetworkProtection:$np|PUA:$pua"`);
    const np = out.includes('NetworkProtection:1') || out.includes('NetworkProtection:2');
    return { id: 'net-domrep', name: 'Domain Reputation Filter', status: np ? 'pass' : 'warn', detail: out, risk: np ? 'low' : 'medium' };
  });
}

export async function checkBeaconing(): Promise<NetCheck> {
  return safe('net-beacon', 'Beaconing Detection', async () => {
    const script = `$ErrorActionPreference='SilentlyContinue'
$conns = Get-NetTCPConnection -State Established -EA SilentlyContinue | Where-Object { $_.RemoteAddress -ne '127.0.0.1' -and $_.RemoteAddress -ne '::1' -and $_.RemoteAddress -ne '0.0.0.0' }
$grouped = $conns | Group-Object RemoteAddress | Where-Object { $_.Count -ge 10 } | Sort-Object Count -Descending | Select-Object -First 20
$results = @()
foreach ($g in $grouped) {
  $ip = $g.Name
  $items = $g.Group
  $pid = ($items | Select-Object -First 1).OwningProcess
  $proc = Get-Process -Id $pid -EA SilentlyContinue
  $pname = if($proc){ $proc.ProcessName } else { "PID:$pid" }
  $ppath = if($proc){ $proc.Path } else { '' }
  $port = ($items | Select-Object -First 1).RemotePort
  $times = @($items | Where-Object { $_.CreationTime } | Sort-Object CreationTime | Select-Object -ExpandProperty CreationTime)
  $avgInt = 0
  if ($times.Count -ge 2) {
    $ints = @()
    for ($i=1; $i -lt $times.Count; $i++) { $ints += ($times[$i] - $times[$i-1]).TotalSeconds }
    $avgInt = [math]::Round(($ints | Measure-Object -Average).Average, 1)
  }
  $results += [PSCustomObject]@{ ip=$ip; port=$port; proc=$pname; pid=$pid; path=$ppath; count=$g.Count; interval=$avgInt }
}
$results | ConvertTo-Json -Depth 2 -Compress`;
    const out = await ps(script, 10000);
    let hosts: { ip: string; port: number; proc: string; pid: number; path: string; count: number; interval: number }[] = [];
    try {
      const parsed = JSON.parse(out || '[]');
      hosts = Array.isArray(parsed) ? parsed : parsed ? [parsed] : [];
    } catch { /* parse failed, count only */ }

    const c = hosts.length;
    const topHost = hosts[0];
    const detailText = c > 0
      ? `${c} hosts with 10+ connections${topHost ? `. Top: ${topHost.proc} → ${topHost.ip}:${topHost.port} (${topHost.count} conns${topHost.interval > 0 ? `, ~${topHost.interval}s interval` : ''})` : ''}`
      : 'No beaconing patterns detected';

    const offenders = hosts.map(h => ({
      label: `${h.ip}:${h.port}`,
      detail: [
        `${h.proc} (PID ${h.pid})`,
        `${h.count} connections`,
        h.interval > 0 ? `every ~${h.interval}s` : '',
        h.path ? h.path.split('\\').pop() : '',
      ].filter(Boolean).join(' · '),
      severity: h.count > 50 ? 'HIGH' : h.count > 20 ? 'MEDIUM' : 'LOW',
    }));

    return {
      id: 'net-beacon',
      name: 'Beaconing Detection',
      status: c === 0 ? 'pass' : 'warn',
      detail: detailText,
      risk: c === 0 ? 'low' : 'high',
      offenders,
    };
  });
}

export async function checkZeroTrust(): Promise<NetCheck> {
  return safe('net-zerotrust', 'Zero-Trust Isolation', async () => {
    const out = await ps(`$pub=(Get-NetFirewallProfile -Name Public).DefaultInboundAction;"PublicInbound:$pub"`);
    const ok = out.includes('Block');
    return { id: 'net-zerotrust', name: 'Zero-Trust Isolation', status: ok ? 'pass' : 'warn', detail: out, risk: ok ? 'low' : 'medium' };
  });
}

export async function checkDPI(): Promise<NetCheck> {
  return safe('net-dpi', 'DPI / TLS Protocol Check', async () => {
    const out = await ps(`$t10=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Client' -EA SilentlyContinue).Enabled;$ssl3=(Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL 3.0\\Client' -EA SilentlyContinue).Enabled;"TLS1.0:$t10|SSL3:$ssl3"`);
    const tls10On = out.includes('TLS1.0:1');
    const ssl3On = out.includes('SSL3:1');
    const insecure = tls10On || ssl3On;
    return { id: 'net-dpi', name: 'DPI / TLS Protocol Check', status: insecure ? 'fail' : 'pass', detail: `${out}${insecure ? ' — deprecated protocols enabled' : ''}`, risk: insecure ? 'high' : 'low' };
  });
}

export async function checkALG(): Promise<NetCheck> {
  return safe('net-alg', 'App Layer Gateway', async () => {
    const out = await ps(`$a=(Get-Service ALG -EA SilentlyContinue).Status;"ALG:$a"`);
    const algRunning = out.includes('ALG:Running');
    return { id: 'net-alg', name: 'App Layer Gateway', status: algRunning ? 'warn' : 'pass', detail: `ALG: ${algRunning ? 'Running — potential bypass vector' : 'Stopped'}`, risk: algRunning ? 'medium' : 'low' };
  });
}

export async function checkSMBKill(): Promise<NetCheck> {
  return safe('net-smbkill', 'SMB Kill-Switch', async () => {
    const out = await ps(`$s1=(Get-SmbServerConfiguration -EA SilentlyContinue).EnableSMB1Protocol;$s2=(Get-SmbServerConfiguration -EA SilentlyContinue).EnableSMB2Protocol;"SMBv1:$s1|SMBv2:$s2"`);
    const smb1Off = out.includes('SMBv1:False');
    return { id: 'net-smbkill', name: 'SMB Kill-Switch', status: smb1Off ? 'pass' : 'fail', detail: out, risk: smb1Off ? 'low' : 'high' };
  });
}

export async function checkNetflow(): Promise<NetCheck> {
  return safe('net-netflow', 'Netflow / Active Connections', async () => {
    const out = await ps(`$e=(Get-NetTCPConnection -State Established -EA SilentlyContinue).Count;$l=(Get-NetTCPConnection -State Listen -EA SilentlyContinue).Count;"Established:$e|Listening:$l"`);
    const estMatch = out.match(/Established:(\d+)/);
    const lisMatch = out.match(/Listening:(\d+)/);
    const est = estMatch ? parseInt(estMatch[1]) : 0;
    const lis = lisMatch ? parseInt(lisMatch[1]) : 0;
    const highActivity = est > 200 || lis > 50;
    return { id: 'net-netflow', name: 'Netflow / Active Connections', status: highActivity ? 'warn' : 'pass', detail: `${est} established, ${lis} listening${highActivity ? ' — unusually high connection count' : ''}`, risk: highActivity ? 'medium' : 'low' };
  });
}

const _yield = () => new Promise<void>(r => setImmediate(r));

export async function runAllNetworkChecks(): Promise<NetCheck[]> {
  const fns: (() => Promise<NetCheck>)[] = [
    checkWFP, checkGeoIP, checkDoH, checkTCPHardening,
    checkOutboundControl, checkTorBlocking, checkPortStealth,
    checkARPProtection, checkDomainReputation, checkBeaconing,
    checkZeroTrust, checkDPI, checkALG, checkSMBKill,
    checkNetflow,
  ];
  const results: NetCheck[] = [];
  for (const fn of fns) {
    results.push(await fn());
    await _yield();
  }
  return results;
}
