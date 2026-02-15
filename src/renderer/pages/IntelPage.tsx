/**
 * SENTINEL UNIFIED — Threat Intelligence Page
 * ARGUS URL scanning with expandable detail sections, scan history,
 * threat timeline with collapsible entries, playbooks.
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { notify } from '../components/Common/SentinelNotification';
import { useTranslation } from 'react-i18next';

// eslint-disable-next-line @typescript-eslint/no-explicit-any
const api = (): any => (window as any).electronAPI;

interface ScanDetail {
  category: string;
  items: { label: string; value: string; severity?: 'safe' | 'warn' | 'danger' | 'info' }[];
}

interface ScanResult {
  url: string;
  safe: boolean;
  score?: number;
  details?: string;
  timestamp?: string;
  // Rich detail fields from ARGUS
  threat_level?: string;
  threat_score?: number;
  reasons?: string[];
  intel?: Record<string, unknown>;
  ssl?: Record<string, unknown>;
  domain?: Record<string, unknown>;
  threats?: string[];
  headers?: Record<string, string>;
  redirects?: string[];
  technologies?: string[];
  whois?: Record<string, unknown>;
  // Extended intel fields
  dns?: Record<string, unknown>;
  geoip?: Record<string, unknown>;
  ip_whois?: Record<string, unknown>;
  reverse_dns?: Record<string, unknown>;
  threat_intel?: Record<string, unknown>;
  resolved_ips?: string[];
  url_params?: Record<string, unknown>;
  content_analysis?: Record<string, unknown>;
  final_destination?: Record<string, unknown>;
  // Two-tier scan fields
  scan_mode?: string;
  deep_fetch?: boolean;
  deep_fetch_available?: boolean;
  deep_fetch_recommended?: boolean;
  deep_fetch_reason?: string;
}

/** Map raw ARGUS response to ScanResult with proper safe/score fields */
function mapArgusResponse(raw: any): ScanResult {
  const threatLevel = (raw.threat_level || 'UNKNOWN').toUpperCase();
  const isSafe = threatLevel === 'SAFE' || threatLevel === 'LOW';
  const threatScore = raw.threat_score ?? 0;
  // Invert: ARGUS threat_score is 0=safe, high=bad → UI score is 0=bad, 100=safe
  const safetyScore = Math.max(0, Math.min(100, 100 - (threatScore * 5)));
  const intel = raw.intel || {};
  return {
    url: raw.url || '',
    safe: isSafe,
    score: safetyScore,
    details: (raw.reasons || []).join(' | ') || threatLevel,
    timestamp: raw.timestamp || new Date().toISOString(),
    threat_level: threatLevel,
    threat_score: threatScore,
    reasons: raw.reasons || [],
    intel,
    ssl: intel.ssl as Record<string, unknown> || undefined,
    domain: intel.domain_analysis as Record<string, unknown> || undefined,
    threats: raw.reasons || [],
    headers: (intel.http as any)?.security_headers || undefined,
    redirects: (intel.redirect_chain as any)?.chain?.map((h: any) => h.url) || undefined,
    technologies: (intel.http as any)?.technologies || undefined,
    whois: intel.whois as Record<string, unknown> || undefined,
    dns: intel.dns as Record<string, unknown> || undefined,
    geoip: intel.geoip as Record<string, unknown> || undefined,
    ip_whois: intel.ip_whois as Record<string, unknown> || undefined,
    reverse_dns: intel.reverse_dns as Record<string, unknown> || undefined,
    threat_intel: intel.threat_intel as Record<string, unknown> || undefined,
    resolved_ips: intel.resolved_ips as string[] || undefined,
    url_params: intel.url_params as Record<string, unknown> || undefined,
    content_analysis: intel.content_analysis as Record<string, unknown> || undefined,
    final_destination: intel.final_destination as Record<string, unknown> || undefined,
    scan_mode: intel.scan_mode as string || raw.deep_fetch ? 'deep' : 'passive',
    deep_fetch: raw.deep_fetch ?? false,
    deep_fetch_available: raw.deep_fetch_available ?? false,
    deep_fetch_recommended: raw.deep_fetch_recommended ?? false,
    deep_fetch_reason: raw.deep_fetch_reason || undefined,
  };
}

interface ThreatEvent {
  id: string;
  timestamp: string;
  type: string;
  severity: string;
  source: string;
  description: string;
  remoteIP?: string;
  actionTaken?: string;
}

type Tab = 'scanner' | 'history' | 'threats' | 'playbooks';

/** Flatten a nested object into label/value pairs for display */
function flattenObj(obj: Record<string, unknown>, prefix = ''): { label: string; value: string; severity: 'safe' | 'warn' | 'danger' | 'info' }[] {
  const items: { label: string; value: string; severity: 'safe' | 'warn' | 'danger' | 'info' }[] = [];
  for (const [k, v] of Object.entries(obj)) {
    if (k.startsWith('_') || k === 'error') continue;
    const label = prefix ? `${prefix}.${k}` : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      items.push(...flattenObj(v as Record<string, unknown>, label).slice(0, 15));
    } else if (Array.isArray(v)) {
      items.push({ label, value: v.length > 0 ? v.map(String).join(', ') : '—', severity: 'info' });
    } else {
      items.push({ label, value: String(v ?? '—'), severity: 'info' });
    }
  }
  return items;
}

/** Parse a ScanResult into expandable detail sections — MAX INFORMATION */
function buildDetailSections(r: ScanResult, t: (key: string) => string): ScanDetail[] {
  const sections: ScanDetail[] = [];

  // ── Overview ──
  const verdictText = r.safe ? t('intel.scanResults.safe') : t('intel.scanResults.potentiallyUnsafe');
  const overview: ScanDetail = { category: t('intel.scanResults.overview'), items: [
    { label: t('intel.scanResults.url'), value: r.url, severity: 'info' },
    { label: t('intel.scanResults.verdict'), value: `${verdictText}${r.threat_level ? ` (${r.threat_level})` : ''}`, severity: r.safe ? 'safe' : 'danger' },
  ]};
  if (r.score !== undefined) overview.items.push({ label: t('intel.scanResults.safetyScore'), value: `${r.score}/100`, severity: r.score > 70 ? 'safe' : r.score > 40 ? 'warn' : 'danger' });
  if (r.threat_score !== undefined) overview.items.push({ label: 'Threat Score', value: String(r.threat_score), severity: r.threat_score === 0 ? 'safe' : r.threat_score < 5 ? 'warn' : 'danger' });
  overview.items.push({ label: 'Scan-Modus', value: r.scan_mode === 'deep' ? 'Tiefe Analyse (HTTP Fetch)' : 'Passive Analyse (kein Fetch)', severity: 'info' });
  if (r.timestamp) overview.items.push({ label: t('intel.scanResults.scanned'), value: new Date(r.timestamp).toLocaleString('de-DE'), severity: 'info' });
  sections.push(overview);

  // ── DNS Records ──
  if (r.dns && typeof r.dns === 'object' && !r.dns.error) {
    const dns = r.dns as Record<string, unknown>;
    const items: ScanDetail['items'] = [];
    if (dns.A) items.push({ label: 'A Records', value: Array.isArray(dns.A) ? dns.A.join(', ') : String(dns.A), severity: 'info' });
    if (dns.AAAA) items.push({ label: 'AAAA Records', value: Array.isArray(dns.AAAA) ? dns.AAAA.join(', ') : String(dns.AAAA), severity: 'info' });
    if (dns.NS) items.push({ label: 'NS Records', value: Array.isArray(dns.NS) ? dns.NS.join(', ') : String(dns.NS), severity: 'info' });
    if (dns.MX) items.push({ label: 'MX Records', value: Array.isArray(dns.MX) ? dns.MX.map((m: any) => typeof m === 'object' ? `${m.priority} ${m.exchange}` : String(m)).join(', ') : String(dns.MX), severity: 'info' });
    if (dns.TXT) items.push({ label: 'TXT Records', value: Array.isArray(dns.TXT) ? dns.TXT.join(' | ') : String(dns.TXT), severity: 'info' });
    if (dns.CNAME) items.push({ label: 'CNAME', value: Array.isArray(dns.CNAME) ? dns.CNAME.join(', ') : String(dns.CNAME), severity: 'info' });
    if (dns.CAA) items.push({ label: 'CAA', value: Array.isArray(dns.CAA) ? dns.CAA.join(', ') : String(dns.CAA), severity: 'info' });
    if (dns.SOA && typeof dns.SOA === 'object') {
      const soa = dns.SOA as Record<string, unknown>;
      items.push({ label: 'SOA', value: `${soa.mname} / ${soa.rname}`, severity: 'info' });
    }
    if (dns.spf) items.push({ label: 'SPF', value: Array.isArray(dns.spf) ? dns.spf.join(' ') : String(dns.spf), severity: 'info' });
    if (dns.dmarc) items.push({ label: 'DMARC', value: Array.isArray(dns.dmarc) ? dns.dmarc.join(' ') : String(dns.dmarc), severity: 'info' });
    if (dns.has_dnssec !== undefined) items.push({ label: 'DNSSEC', value: dns.has_dnssec ? 'Aktiv' : 'Nicht vorhanden', severity: dns.has_dnssec ? 'safe' : 'warn' });
    if (items.length > 0) sections.push({ category: 'DNS Records', items });
  }

  // ── Resolved IPs ──
  if (r.resolved_ips && r.resolved_ips.length > 0) {
    sections.push({ category: 'Resolved IPs', items: r.resolved_ips.map((ip, i) => ({
      label: `IP ${i + 1}`, value: ip, severity: 'info' as const,
    }))});
  }

  // ── GeoIP ──
  if (r.geoip && typeof r.geoip === 'object' && !(r.geoip as any).error) {
    const geo = r.geoip as Record<string, unknown>;
    const items: ScanDetail['items'] = [];
    if (geo.country) items.push({ label: 'Land', value: String(geo.country), severity: 'info' });
    if (geo.country_code) items.push({ label: 'Ländercode', value: String(geo.country_code), severity: 'info' });
    if (geo.region) items.push({ label: 'Region', value: String(geo.region), severity: 'info' });
    if (geo.city) items.push({ label: 'Stadt', value: String(geo.city), severity: 'info' });
    if (geo.latitude !== undefined) items.push({ label: 'Koordinaten', value: `${geo.latitude}, ${geo.longitude}`, severity: 'info' });
    if (geo.asn) items.push({ label: 'ASN', value: String(geo.asn), severity: 'info' });
    if (geo.org || geo.organization) items.push({ label: 'Organisation', value: String(geo.org || geo.organization), severity: 'info' });
    if (geo.isp) items.push({ label: 'ISP', value: String(geo.isp), severity: 'info' });
    if (geo.is_hosting !== undefined) items.push({ label: 'Hosting', value: geo.is_hosting ? 'Ja' : 'Nein', severity: 'info' });
    if (geo.is_tor !== undefined) items.push({ label: 'Tor Exit', value: geo.is_tor ? 'Ja' : 'Nein', severity: geo.is_tor ? 'danger' : 'safe' });
    if (geo.is_vpn !== undefined) items.push({ label: 'VPN', value: geo.is_vpn ? 'Ja' : 'Nein', severity: 'info' });
    if (items.length > 0) sections.push({ category: 'GeoIP', items });
  }

  // ── SSL/TLS ──
  if (r.ssl && typeof r.ssl === 'object' && !(r.ssl as any).error) {
    const ssl = r.ssl as Record<string, unknown>;
    const items: ScanDetail['items'] = [];
    if (ssl.issuer) items.push({ label: 'Aussteller', value: typeof ssl.issuer === 'object' ? JSON.stringify(ssl.issuer) : String(ssl.issuer), severity: 'info' });
    if (ssl.subject) items.push({ label: 'Subjekt', value: typeof ssl.subject === 'object' ? JSON.stringify(ssl.subject) : String(ssl.subject), severity: 'info' });
    if (ssl.not_before) items.push({ label: 'Gültig ab', value: String(ssl.not_before), severity: 'info' });
    if (ssl.not_after) items.push({ label: 'Gültig bis', value: String(ssl.not_after), severity: 'info' });
    if (ssl.protocol_version) items.push({ label: 'Protokoll', value: String(ssl.protocol_version), severity: 'info' });
    if (ssl.cipher_suite) items.push({ label: 'Cipher', value: String(ssl.cipher_suite), severity: 'info' });
    if (ssl.san) items.push({ label: 'SAN', value: Array.isArray(ssl.san) ? ssl.san.join(', ') : String(ssl.san), severity: 'info' });
    if (ssl.valid !== undefined) items.push({ label: 'Gültig', value: ssl.valid ? 'Ja' : 'Nein', severity: ssl.valid ? 'safe' : 'danger' });
    if (ssl.expired !== undefined) items.push({ label: 'Abgelaufen', value: ssl.expired ? 'Ja' : 'Nein', severity: ssl.expired ? 'danger' : 'safe' });
    if (ssl.days_until_expiry !== undefined) items.push({ label: 'Tage bis Ablauf', value: String(ssl.days_until_expiry), severity: Number(ssl.days_until_expiry) < 30 ? 'warn' : 'safe' });
    if (ssl.key_size) items.push({ label: 'Schlüsselgröße', value: `${ssl.key_size} bit`, severity: Number(ssl.key_size) >= 2048 ? 'safe' : 'warn' });
    if (ssl.signature_algorithm) items.push({ label: 'Signatur', value: String(ssl.signature_algorithm), severity: 'info' });
    if (ssl.ocsp_stapling !== undefined) items.push({ label: 'OCSP Stapling', value: ssl.ocsp_stapling ? 'Ja' : 'Nein', severity: 'info' });
    if (items.length > 0) sections.push({ category: 'SSL / TLS', items });
  }

  // ── WHOIS ──
  if (r.whois && typeof r.whois === 'object' && !(r.whois as any).error) {
    const w = r.whois as Record<string, unknown>;
    const items: ScanDetail['items'] = [];
    if (w.registrar) items.push({ label: 'Registrar', value: String(w.registrar), severity: 'info' });
    if (w.creation_date) items.push({ label: 'Erstellt', value: String(w.creation_date), severity: 'info' });
    if (w.expiration_date) items.push({ label: 'Ablauf', value: String(w.expiration_date), severity: 'info' });
    if (w.domain_age_days !== undefined) items.push({ label: 'Alter (Tage)', value: String(w.domain_age_days), severity: Number(w.domain_age_days) < 90 ? 'warn' : 'safe' });
    if (w.updated_date) items.push({ label: 'Aktualisiert', value: String(w.updated_date), severity: 'info' });
    if (w.name_servers) items.push({ label: 'Nameserver', value: Array.isArray(w.name_servers) ? w.name_servers.join(', ') : String(w.name_servers), severity: 'info' });
    if (w.registrant_country) items.push({ label: 'Registrant Land', value: String(w.registrant_country), severity: 'info' });
    if (w.privacy !== undefined) items.push({ label: 'Privacy Protection', value: w.privacy ? 'Aktiv' : 'Nein', severity: 'info' });
    if (w.newly_registered !== undefined) items.push({ label: 'Neu registriert', value: w.newly_registered ? 'Ja' : 'Nein', severity: w.newly_registered ? 'warn' : 'safe' });
    if (items.length > 0) sections.push({ category: 'WHOIS', items });
  }

  // ── Domain-Analyse ──
  if (r.domain && typeof r.domain === 'object' && !(r.domain as any).error) {
    const dom = r.domain as Record<string, unknown>;
    const items: ScanDetail['items'] = [];
    if (dom.typosquatting && typeof dom.typosquatting === 'object') {
      const ts = dom.typosquatting as Record<string, unknown>;
      items.push({ label: 'Typosquatting', value: ts.is_typosquat ? `Ja — Ziel: ${ts.target_brand}` : 'Nein', severity: ts.is_typosquat ? 'danger' : 'safe' });
      if (ts.homoglyph_detected) items.push({ label: 'Homoglyph', value: 'Erkannt', severity: 'danger' });
      if (ts.distance !== undefined) items.push({ label: 'Levenshtein-Distanz', value: String(ts.distance), severity: 'info' });
    }
    if (dom.registrar_risk !== undefined) items.push({ label: 'Registrar-Risiko', value: String(dom.registrar_risk), severity: Number(dom.registrar_risk) > 5 ? 'warn' : 'safe' });
    if (dom.whois_privacy !== undefined) items.push({ label: 'WHOIS Privacy', value: String(dom.whois_privacy), severity: 'info' });
    if (dom.entropy !== undefined) items.push({ label: 'Domain-Entropie', value: String(Number(dom.entropy).toFixed(2)), severity: Number(dom.entropy) > 4 ? 'warn' : 'info' });
    // Remaining fields
    for (const [k, v] of Object.entries(dom)) {
      if (['typosquatting', 'registrar_risk', 'whois_privacy', 'entropy', 'error'].includes(k)) continue;
      if (v !== null && v !== undefined && typeof v !== 'object') {
        items.push({ label: k, value: String(v), severity: 'info' });
      }
    }
    if (items.length > 0) sections.push({ category: 'Domain-Analyse', items });
  }

  // ── Threat Intel ──
  if (r.threat_intel && typeof r.threat_intel === 'object' && !(r.threat_intel as any).error) {
    const ti = r.threat_intel as Record<string, unknown>;
    const items: ScanDetail['items'] = [];
    if (ti.verdict) items.push({ label: 'Verdict', value: String(ti.verdict), severity: ti.verdict === 'clean' ? 'safe' : ti.verdict === 'suspicious' ? 'warn' : 'danger' });
    if (ti.score !== undefined) items.push({ label: 'Score', value: String(ti.score), severity: Number(ti.score) > 5 ? 'danger' : Number(ti.score) > 0 ? 'warn' : 'safe' });
    // Source-specific results
    for (const src of ['virustotal', 'abuseipdb', 'alienvault_otx', 'ipinfo']) {
      const srcData = ti[src];
      if (srcData && typeof srcData === 'object') {
        const sd = srcData as Record<string, unknown>;
        if (sd.error) {
          items.push({ label: src, value: `Fehler: ${sd.error}`, severity: 'warn' });
        } else {
          for (const [k, v] of Object.entries(sd)) {
            if (k === 'error' || k.startsWith('_')) continue;
            if (v !== null && v !== undefined) {
              items.push({ label: `${src}.${k}`, value: typeof v === 'object' ? JSON.stringify(v) : String(v), severity: 'info' });
            }
          }
        }
      }
    }
    if (items.length > 0) sections.push({ category: 'Threat Intelligence', items });
  }

  // ── Reverse DNS ──
  if (r.reverse_dns && typeof r.reverse_dns === 'object' && !(r.reverse_dns as any).error) {
    const items = flattenObj(r.reverse_dns as Record<string, unknown>);
    if (items.length > 0) sections.push({ category: 'Reverse DNS', items });
  }

  // ── IP WHOIS ──
  if (r.ip_whois && typeof r.ip_whois === 'object' && !(r.ip_whois as any).error) {
    const items = flattenObj(r.ip_whois as Record<string, unknown>);
    if (items.length > 0) sections.push({ category: 'IP WHOIS', items });
  }

  // ── Threat Indicators (reasons) ──
  if (r.threats && r.threats.length > 0) {
    sections.push({ category: 'Threat Indicators', items: r.threats.map((th, i) => ({
      label: `#${i + 1}`, value: th, severity: 'danger' as const,
    }))});
  }

  // ── HTTP Headers (deep fetch only) ──
  if (r.headers && typeof r.headers === 'object') {
    const hdr = r.headers as Record<string, string>;
    const items = Object.entries(hdr).slice(0, 25).map(([k, v]) => ({
      label: k, value: String(v), severity: 'info' as const,
    }));
    if (items.length > 0) sections.push({ category: 'HTTP Security Headers', items });
  }

  // ── Redirects (deep fetch only) ──
  if (r.redirects && r.redirects.length > 0) {
    sections.push({ category: 'Redirect-Kette', items: r.redirects.map((u, i) => ({
      label: `Hop ${i + 1}`, value: u, severity: 'info' as const,
    }))});
  }

  // ── Content Analysis (deep fetch only) ──
  if (r.content_analysis && typeof r.content_analysis === 'object' && !(r.content_analysis as any).error) {
    const items = flattenObj(r.content_analysis as Record<string, unknown>);
    if (items.length > 0) sections.push({ category: 'Content-Analyse', items });
  }

  // ── Technologies (deep fetch only) ──
  if (r.technologies && r.technologies.length > 0) {
    sections.push({ category: 'Technologien', items: r.technologies.map((tech) => ({
      label: tech, value: 'Erkannt', severity: 'info' as const,
    }))});
  }

  // ── Final Destination ──
  if (r.final_destination && typeof r.final_destination === 'object') {
    const fd = r.final_destination as Record<string, unknown>;
    const items: ScanDetail['items'] = [];
    if (fd.url) items.push({ label: 'URL', value: String(fd.url), severity: 'info' });
    if (fd.domain) items.push({ label: 'Domain', value: String(fd.domain), severity: 'info' });
    if (fd.verdict) items.push({ label: 'Verdict', value: String(fd.verdict), severity: fd.verdict === 'SAFE' ? 'safe' : fd.verdict === 'SUSPICIOUS' ? 'warn' : 'danger' });
    if (fd.risk_score !== undefined) items.push({ label: 'Risiko-Score', value: String(fd.risk_score), severity: Number(fd.risk_score) > 50 ? 'danger' : Number(fd.risk_score) > 20 ? 'warn' : 'safe' });
    if (fd.in_blacklist !== undefined) items.push({ label: 'Blacklist', value: fd.in_blacklist ? 'Ja' : 'Nein', severity: fd.in_blacklist ? 'danger' : 'safe' });
    if (items.length > 0) sections.push({ category: 'Ziel-Analyse', items });
  }

  // ── URL-Parameter ──
  if (r.url_params && typeof r.url_params === 'object') {
    const up = r.url_params as Record<string, unknown>;
    const items = flattenObj(up);
    if (items.length > 0) sections.push({ category: 'URL-Parameter', items });
  }

  // Raw details fallback
  if (r.details && sections.length <= 1) {
    sections.push({ category: 'Details', items: [{ label: 'Info', value: r.details, severity: 'info' }] });
  }

  return sections;
}

const sevColor = (s?: string) => {
  if (s === 'safe') return 'var(--s-green)';
  if (s === 'warn') return 'var(--s-amber)';
  if (s === 'danger') return 'var(--s-red)';
  return 'var(--s-text-secondary)';
};

const IntelPage: React.FC = () => {
  const { t } = useTranslation();
  const location = useLocation();
  const navState = (location.state || {}) as { scanUrl?: string; source?: string };

  const [tab, setTab] = useState<Tab>(navState.scanUrl ? 'scanner' : 'scanner');
  const [scanUrl, setScanUrl] = useState(navState.scanUrl || '');
  const [scanning, setScanning] = useState(false);
  const [deepScanning, setDeepScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [expandedSections, setExpandedSections] = useState<Set<string>>(new Set([t('intel.scanResults.overview')]));
  const [history, setHistory] = useState<ScanResult[]>([]);
  const [threats, setThreats] = useState<ThreatEvent[]>([]);
  const [expandedThreats, setExpandedThreats] = useState<Set<string>>(new Set());
  const [argusHealth, setArgusHealth] = useState<{ running: boolean; port: number; status?: string; lastError?: string | null; uptimeMs?: number } | null>(null);
  const [argusRestarting, setArgusRestarting] = useState(false);

  const fetchData = useCallback(async () => {
    try {
      const a = api();
      if (a?.argus?.getHealth) {
        const h = await a.argus.getHealth();
        if (h?.data) {
          const d = h.data as any;
          setArgusHealth({ running: d.status === 'running' || d.running === true, port: d.port || 8080, status: d.status, lastError: d.lastError, uptimeMs: d.uptimeMs });
        }
      }
      if (a?.argus?.getScanHistory) {
        const r = await a.argus.getScanHistory();
        if (r?.data && Array.isArray(r.data)) setHistory(r.data.map((e: any) => mapArgusResponse(e)));
      }
      if (a?.shield?.getThreatEvents) {
        const t = await a.shield.getThreatEvents({});
        if (t?.events && Array.isArray(t.events)) setThreats(t.events);
      }
    } catch (e: any) { console.warn('[IntelPage] fetchData:', e?.message); }
  }, []);

  useEffect(() => { fetchData(); const i = setInterval(fetchData, 15000); return () => clearInterval(i); }, [fetchData]);

  const handleRestartArgus = async () => {
    setArgusRestarting(true);
    try {
      await api()?.argus?.restart?.();
      await new Promise<void>((r) => setTimeout(r, 3000));
      await fetchData();
      notify.success('ARGUS restarted');
    } catch (e: any) { notify.error(e?.message || 'ARGUS restart failed'); }
    setArgusRestarting(false);
  };

  const handleScan = async (deepFetch = false) => {
    if (!scanUrl.trim()) return;
    if (deepFetch) { setDeepScanning(true); } else { setScanning(true); setScanResult(null); }
    setExpandedSections(new Set([t('intel.scanResults.overview')]));
    try {
      const r = await api()?.argus?.scanUrl?.(scanUrl.trim(), deepFetch);
      if (r?.data) {
        const mapped = mapArgusResponse(r.data);
        setScanResult(mapped);
        const levelEmoji = mapped.safe ? '🟢' : mapped.threat_level === 'SUSPICIOUS' ? '🟡' : '🔴';
        const modeLabel = deepFetch ? 'Tiefe Analyse' : 'Passive Analyse';
        notify.success(`${levelEmoji} ${modeLabel}: ${mapped.threat_level} — ${scanUrl}`);
      } else {
        setScanResult({ url: scanUrl, safe: false, details: r?.error || 'Scan failed' });
        notify.error(r?.error || 'Scan returned no data');
      }
      fetchData();
    } catch (e: any) {
      setScanResult({ url: scanUrl, safe: false, details: String(e) });
      notify.error(e?.message || 'Scan failed');
    }
    setScanning(false);
    setDeepScanning(false);
  };

  const handleDeepScan = () => handleScan(true);

  const handleBatchScan = async () => {
    const urls = scanUrl.split('\n').map((u) => u.trim()).filter(Boolean);
    if (urls.length === 0) return;
    setScanning(true);
    try {
      await api()?.argus?.batchScan?.(urls);
      fetchData();
      notify.success(`Batch scan of ${urls.length} URLs complete`);
    } catch (e: any) { notify.error(e?.message || 'Batch scan failed'); }
    setScanning(false);
  };

  const handleClearHistory = async () => {
    await api()?.argus?.clearHistory?.();
    setHistory([]);
  };

  const toggleSection = (cat: string) => {
    setExpandedSections((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat); else next.add(cat);
      return next;
    });
  };

  const toggleThreat = (id: string) => {
    setExpandedThreats((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const detailSections = scanResult ? buildDetailSections(scanResult, t) : [];

  const TABS: { key: Tab; labelKey: string; count?: number }[] = [
    { key: 'scanner', labelKey: 'intel.tabs.scanner' },
    { key: 'history', labelKey: 'intel.tabs.history', count: history.length },
    { key: 'threats', labelKey: 'intel.tabs.threats', count: threats.length },
    { key: 'playbooks', labelKey: 'intel.tabs.playbooks' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* ─── Spacy Header ─── */}
      <div className="s-page-header">
        <div className="s-tab-bar">
          {TABS.map((tb) => (
            <button key={tb.key} className={`s-tab ${tab === tb.key ? 's-tab-active' : ''}`} onClick={() => setTab(tb.key)}>
              {t(tb.labelKey)}
              {tb.count !== undefined && <span className="s-tab-badge">{tb.count}</span>}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '3px 10px', borderRadius: 8,
            background: argusHealth?.running ? 'rgba(61,255,143,0.06)' : 'rgba(255,95,95,0.06)',
            border: `1px solid ${argusHealth?.running ? 'rgba(61,255,143,0.18)' : 'rgba(255,95,95,0.18)'}`,
          }}>
            <span style={{
              width: 6, height: 6, borderRadius: '50%',
              background: argusHealth?.running ? 'var(--s-green)' : 'var(--s-red)',
              boxShadow: `0 0 6px ${argusHealth?.running ? 'var(--s-green)' : 'var(--s-red)'}`,
              animation: argusHealth?.running ? 'pulse-green 2s ease-in-out infinite' : 'pulse-red 1.5s ease-in-out infinite',
            }} />
            <span style={{ fontSize: '0.7rem', fontWeight: 600, color: argusHealth?.running ? 'var(--s-green)' : 'var(--s-red)' }}>
              ARGUS {argusHealth?.running ? `${t('intel.argus.online')} :${argusHealth.port}` : t('intel.argus.offline')}
            </span>
          </div>
          {!argusHealth?.running && (
            <button
              className="s-btn s-btn-primary s-btn-sm"
              style={{ fontSize: '0.65rem', padding: '3px 10px' }}
              onClick={handleRestartArgus}
              disabled={argusRestarting}
            >
              {argusRestarting ? t('intel.argus.starting') : `▶ ${t('common.start')}`}
            </button>
          )}
        </div>
      </div>

      <AnimatePresence mode="wait">
        {/* ═══ Scanner Tab ═══ */}
        {tab === 'scanner' && (
          <motion.div key="scanner" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
            {/* Rich offline state when ARGUS is not running */}
            {argusHealth && !argusHealth.running && (
              <div className="s-card-spacy" style={{ borderColor: 'rgba(255,95,95,0.25)', background: 'rgba(255,95,95,0.03)' }}>
                <div style={{ display: 'flex', alignItems: 'flex-start', gap: 16 }}>
                  <div style={{
                    width: 52, height: 52, borderRadius: 14, flexShrink: 0,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    background: 'rgba(255,95,95,0.1)', border: '1px solid rgba(255,95,95,0.25)',
                    fontSize: 24,
                  }}>
                    🧠
                  </div>
                  <div style={{ flex: 1 }}>
                    <div style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--s-red)', marginBottom: 4 }}>
                      {t('intel.argus.offline')}
                    </div>
                    <div style={{ fontSize: '0.8125rem', color: 'var(--s-text-muted)', lineHeight: 1.6 }}>
                      {t('vault.argusEncryption.noArgus')}
                    </div>
                    {argusHealth.lastError && (
                      <div style={{ fontSize: '0.75rem', color: 'var(--s-red)', marginTop: 6, fontFamily: 'var(--s-font-mono)', padding: '4px 8px', background: 'rgba(255,95,95,0.06)', borderRadius: 6, border: '1px solid rgba(255,95,95,0.15)' }}>
                        {argusHealth.lastError}
                      </div>
                    )}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12 }}>
                      <button
                        className="s-btn s-btn-primary s-btn-sm"
                        onClick={handleRestartArgus}
                        disabled={argusRestarting}
                      >
                        {argusRestarting ? t('intel.argus.starting') : `▶ ${t('intel.argus.start')}`}
                      </button>
                      <button className="s-btn s-btn-ghost s-btn-sm" onClick={fetchData}>↻ {t('common.retry')}</button>
                    </div>
                    <div style={{ marginTop: 14, padding: '10px 12px', background: 'rgba(109,120,255,0.04)', borderRadius: 8, border: '1px solid rgba(109,120,255,0.08)' }}>
                      <div style={{ fontSize: '0.6875rem', fontWeight: 600, color: 'var(--s-text-dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 6 }}>
                        Available while offline
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 3, fontSize: '0.75rem', color: 'var(--s-text-muted)' }}>
                        <span>• View previous scan history in the History tab</span>
                        <span>• Review recorded threat events in the Timeline tab</span>
                        <span>• Shield firewall and network monitoring remain active</span>
                        <span>• Local security scans run independently of ARGUS</span>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            <div className="s-card-spacy">
              <div className="s-heading-md" style={{ marginBottom: 16 }}>{t('intel.scanner.title')}</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <textarea
                  className="s-input"
                  placeholder={t('intel.scanner.urlPlaceholder')}
                  value={scanUrl}
                  onChange={(e) => setScanUrl(e.target.value)}
                  rows={3}
                  style={{ resize: 'vertical', minHeight: 48 }}
                  onKeyDown={(e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); handleScan(); } }}
                />
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="s-btn s-btn-primary" onClick={() => handleScan()} disabled={scanning || !scanUrl.trim() || (argusHealth !== null && !argusHealth.running)}>
                    {scanning ? t('intel.scanner.scanning') : argusHealth && !argusHealth.running ? t('intel.argus.offline') : t('intel.scanner.scan')}
                  </button>
                  <button className="s-btn s-btn-ghost" onClick={handleBatchScan} disabled={scanning || !scanUrl.trim() || (argusHealth !== null && !argusHealth.running)}>
                    {t('intel.scanner.batchScan')}
                  </button>
                </div>
              </div>
            </div>

            {/* Scan Result with expandable sections */}
            {scanResult && (
              <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {/* Result header */}
                <div className="s-card-spacy" style={{
                  borderColor: scanResult.safe ? 'rgba(61,255,143,0.3)' : 'rgba(255,95,95,0.3)',
                  borderBottomLeftRadius: detailSections.length > 0 ? 0 : undefined,
                  borderBottomRightRadius: detailSections.length > 0 ? 0 : undefined,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    <div style={{
                      width: 48, height: 48, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: scanResult.safe ? 'rgba(61,255,143,0.1)' : 'rgba(255,95,95,0.1)',
                      border: `2px solid ${scanResult.safe ? 'rgba(61,255,143,0.3)' : 'rgba(255,95,95,0.3)'}`,
                      fontSize: 20,
                    }}>
                      {scanResult.safe ? '✓' : '!'}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontWeight: 700, fontSize: '1rem', color: scanResult.safe ? 'var(--s-green)' : 'var(--s-red)' }}>
                        {scanResult.safe ? t('intel.scanner.safe') : t('intel.scanner.suspicious')}
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', fontFamily: 'var(--s-font-mono)' }}>{scanResult.url}</div>
                    </div>
                    {scanResult.score !== undefined && (
                      <div style={{ textAlign: 'center' }}>
                        <div style={{
                          fontSize: '1.5rem', fontWeight: 800, fontFamily: 'var(--s-font-display)',
                          color: scanResult.score > 70 ? 'var(--s-green)' : scanResult.score > 40 ? 'var(--s-amber)' : 'var(--s-red)',
                        }}>
                          {scanResult.score}
                        </div>
                        <div style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)' }}>/ 100</div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Expandable detail sections */}
                {detailSections.map((section) => {
                  const isOpen = expandedSections.has(section.category);
                  return (
                    <div key={section.category} style={{
                      border: '1px solid var(--s-border)',
                      borderTop: 'none',
                      background: 'var(--s-bg-card)',
                    }}>
                      <button
                        onClick={() => toggleSection(section.category)}
                        style={{
                          width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                          padding: '10px 18px', background: 'none', border: 'none', cursor: 'pointer',
                          color: 'var(--s-text)', fontSize: '0.8125rem', fontWeight: 600,
                        }}
                      >
                        <span>{section.category} ({section.items.length})</span>
                        <span style={{ fontSize: '0.7rem', color: 'var(--s-text-dim)', transition: 'transform 0.2s', transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}>▼</span>
                      </button>
                      {isOpen && (
                        <div style={{ padding: '0 18px 12px' }}>
                          {section.items.map((item, idx) => (
                            <div key={`${item.label}-${idx}`} style={{
                              display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
                              padding: '4px 0', borderBottom: idx < section.items.length - 1 ? '1px solid rgba(109,120,255,0.06)' : 'none',
                            }}>
                              <span style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', flexShrink: 0, marginRight: 12 }}>{item.label}</span>
                              <span style={{
                                fontSize: '0.75rem', fontFamily: 'var(--s-font-mono)', fontWeight: 600,
                                color: sevColor(item.severity), textAlign: 'right', wordBreak: 'break-all',
                              }}>
                                {item.value}
                              </span>
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  );
                })}

                {/* Expand/Collapse all */}
                {detailSections.length > 1 && (
                  <div style={{ display: 'flex', justifyContent: 'center', padding: '8px 0' }}>
                    <button className="s-btn s-btn-ghost s-btn-sm" style={{ fontSize: '0.65rem' }} onClick={() => {
                      if (expandedSections.size === detailSections.length) {
                        setExpandedSections(new Set());
                      } else {
                        setExpandedSections(new Set(detailSections.map((s) => s.category)));
                      }
                    }}>
                      {expandedSections.size === detailSections.length ? 'Alles einklappen' : 'Alles aufklappen'}
                    </button>
                  </div>
                )}

                {/* ── Deep Fetch Warning Banner ── */}
                {scanResult.deep_fetch_available && !scanResult.deep_fetch && (
                  <div style={{
                    border: `1px solid ${scanResult.deep_fetch_recommended ? 'rgba(255,190,61,0.35)' : 'rgba(109,120,255,0.15)'}`,
                    borderTop: 'none',
                    background: scanResult.deep_fetch_recommended ? 'rgba(255,190,61,0.04)' : 'rgba(109,120,255,0.03)',
                    padding: '14px 18px',
                    borderBottomLeftRadius: 12,
                    borderBottomRightRadius: 12,
                  }}>
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                      <div style={{
                        width: 36, height: 36, borderRadius: 10, flexShrink: 0,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        background: scanResult.deep_fetch_recommended ? 'rgba(255,190,61,0.12)' : 'rgba(109,120,255,0.08)',
                        border: `1px solid ${scanResult.deep_fetch_recommended ? 'rgba(255,190,61,0.25)' : 'rgba(109,120,255,0.15)'}`,
                        fontSize: 16,
                      }}>
                        {scanResult.deep_fetch_recommended ? '⚠' : '🔍'}
                      </div>
                      <div style={{ flex: 1 }}>
                        <div style={{ fontWeight: 700, fontSize: '0.8125rem', color: scanResult.deep_fetch_recommended ? 'var(--s-amber)' : 'var(--s-text)', marginBottom: 4 }}>
                          {scanResult.deep_fetch_recommended ? 'Tiefe Analyse empfohlen' : 'Tiefe Analyse verfügbar'}
                        </div>
                        <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', lineHeight: 1.5 }}>
                          {scanResult.deep_fetch_recommended && scanResult.deep_fetch_reason
                            ? scanResult.deep_fetch_reason.split(' | ').map((r, i) => (
                              <span key={i} style={{ display: 'block' }}>• {r}</span>
                            ))
                            : 'HTTP-Inhalte abrufen, Redirect-Kette verfolgen und Content analysieren.'
                          }
                        </div>
                        <div style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', marginTop: 6, padding: '4px 8px', background: 'rgba(255,190,61,0.06)', borderRadius: 6, border: '1px solid rgba(255,190,61,0.1)' }}>
                          Hinweis: Die tiefe Analyse stellt eine HTTP-Verbindung zur Ziel-URL her und lädt Inhalte herunter.
                        </div>
                        <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
                          <button
                            className="s-btn s-btn-primary s-btn-sm"
                            onClick={handleDeepScan}
                            disabled={deepScanning || (argusHealth !== null && !argusHealth.running)}
                            style={{ fontSize: '0.75rem' }}
                          >
                            {deepScanning ? 'Analysiere...' : 'Tiefe Analyse starten'}
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* ── Deep fetch completed badge ── */}
                {scanResult.deep_fetch && (
                  <div style={{
                    border: '1px solid rgba(61,255,143,0.2)', borderTop: 'none',
                    background: 'rgba(61,255,143,0.03)', padding: '8px 18px',
                    borderBottomLeftRadius: 12, borderBottomRightRadius: 12,
                    display: 'flex', alignItems: 'center', gap: 8,
                  }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--s-green)', fontWeight: 600 }}>
                      Tiefe Analyse abgeschlossen — HTTP-Inhalte, Redirects und Content wurden analysiert
                    </span>
                  </div>
                )}
              </motion.div>
            )}
          </motion.div>
        )}

        {/* ═══ History Tab ═══ */}
        {tab === 'history' && (
          <motion.div key="history" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="s-flex-between" style={{ padding: '14px 18px', borderBottom: '1px solid var(--s-border)' }}>
              <span className="s-heading-sm">Scan History ({history.length})</span>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="s-btn s-btn-ghost s-btn-sm" onClick={async () => { await api()?.argus?.exportHistory?.(); }}>Export</button>
                <button className="s-btn s-btn-danger s-btn-sm" onClick={handleClearHistory}>Clear</button>
              </div>
            </div>
            <div style={{ maxHeight: 450, overflowY: 'auto' }}>
              {history.length === 0 ? (
                <div style={{ textAlign: 'center', padding: 40, color: 'var(--s-text-dim)' }}>No scan history</div>
              ) : history.map((entry, i) => (
                <div
                  key={`h-${i}`}
                  style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 18px', borderBottom: '1px solid rgba(109,120,255,0.06)', cursor: 'pointer' }}
                  onClick={() => { setScanResult(entry); setExpandedSections(new Set([t('intel.scanResults.overview')])); setTab('scanner'); }}
                >
                  <span className={`s-status-dot ${entry.safe ? 's-status-dot-online' : 's-status-dot-error'}`} />
                  <span style={{ flex: 1, fontFamily: 'var(--s-font-mono)', fontSize: '0.8125rem' }} className="s-truncate">{entry.url}</span>
                  {entry.score !== undefined && (
                    <span className={`s-badge ${entry.score > 70 ? 's-badge-green' : entry.score > 40 ? 's-badge-amber' : 's-badge-red'}`}>{entry.score}</span>
                  )}
                  <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', fontFamily: 'var(--s-font-mono)' }}>
                    {entry.timestamp ? new Date(entry.timestamp).toLocaleString('de-DE') : '—'}
                  </span>
                </div>
              ))}
            </div>
          </motion.div>
        )}

        {/* ═══ Threats Tab ═══ */}
        {tab === 'threats' && (
          <motion.div key="threats" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {threats.length === 0 ? (
              <div className="s-card-spacy" style={{ textAlign: 'center', padding: 40, color: 'var(--s-text-dim)' }}>No threat events recorded</div>
            ) : threats.slice(0, 50).map((t) => {
              const isOpen = expandedThreats.has(t.id);
              return (
                <div key={t.id} className="s-card-compact-spacy" style={{ cursor: 'pointer' }} onClick={() => toggleThreat(t.id)}>
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
                    <div style={{
                      width: 8, height: 8, borderRadius: '50%', marginTop: 6, flexShrink: 0,
                      background: t.severity === 'critical' ? 'var(--s-red)' : t.severity === 'high' ? 'var(--s-amber)' : 'var(--s-cyan)',
                      boxShadow: `0 0 8px ${t.severity === 'critical' ? 'rgba(255,95,95,0.5)' : t.severity === 'high' ? 'rgba(255,190,61,0.5)' : 'rgba(60,240,255,0.3)'}`,
                    }} />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontWeight: 600, fontSize: '0.8125rem' }}>{t.type}</span>
                        <span className={`s-badge ${t.severity === 'critical' ? 's-badge-red' : t.severity === 'high' ? 's-badge-amber' : 's-badge-cyan'}`}>{t.severity}</span>
                        <span style={{ fontSize: '0.6875rem', color: 'var(--s-text-dim)', marginLeft: 'auto', fontFamily: 'var(--s-font-mono)' }}>
                          {new Date(t.timestamp).toLocaleString('de-DE')}
                        </span>
                        <span style={{ fontSize: '0.6rem', color: 'var(--s-text-dim)', transition: 'transform 0.2s', transform: isOpen ? 'rotate(180deg)' : 'rotate(0deg)' }}>▼</span>
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--s-text-muted)', marginTop: 4 }}>{t.description}</div>
                    </div>
                  </div>
                  {isOpen && (
                    <div style={{ marginTop: 10, padding: '10px 14px', background: 'rgba(8,8,28,0.3)', borderRadius: 'var(--s-radius-sm)' }}>
                      {[
                        { label: 'Source', value: t.source },
                        { label: 'Remote IP', value: t.remoteIP || '—' },
                        { label: 'Action Taken', value: t.actionTaken || '—' },
                        { label: 'Severity', value: t.severity },
                        { label: 'Timestamp', value: new Date(t.timestamp).toLocaleString('de-DE') },
                      ].map((item) => (
                        <div key={item.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '3px 0', borderBottom: '1px solid rgba(109,120,255,0.04)' }}>
                          <span style={{ fontSize: '0.7rem', color: 'var(--s-text-dim)' }}>{item.label}</span>
                          <span style={{ fontSize: '0.7rem', fontFamily: 'var(--s-font-mono)', fontWeight: 600 }}>{item.value}</span>
                        </div>
                      ))}
                      {t.remoteIP && t.remoteIP !== '—' && (
                        <div style={{ marginTop: 8, display: 'flex', gap: 6 }}>
                          <button className="s-btn s-btn-danger s-btn-sm" style={{ fontSize: '0.6rem', padding: '2px 8px' }} onClick={(e) => {
                            e.stopPropagation();
                            api()?.shield?.blockIP?.(t.remoteIP, `Blocked from threat: ${t.type}`);
                          }}>Block IP</button>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </motion.div>
        )}

        {/* ═══ Playbooks Tab ═══ */}
        {tab === 'playbooks' && (
          <motion.div key="playbooks" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="s-card-spacy">
            <div className="s-heading-md" style={{ marginBottom: 16 }}>{t('intel.playbooks.title')}</div>
            <div style={{ textAlign: 'center', padding: 40, color: 'var(--s-text-dim)' }}>
              <div style={{ fontSize: 32, marginBottom: 12 }}>📋</div>
              <div>Playbook management coming soon</div>
              <div style={{ fontSize: '0.75rem', marginTop: 4 }}>Create automated response playbooks for threat events</div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
};

export default IntelPage;
