/**
 * SENTINEL UNIFIED — ARGUS TypeScript Types
 * Types for all ARGUS Python backend responses.
 */

export interface ArgusScanResult {
  url: string;
  threat_level: 'SAFE' | 'SUSPICIOUS' | 'MALICIOUS' | 'CRITICAL' | 'UNKNOWN';
  threat_score?: number;
  reasons?: string[];
  intel?: ArgusIntel;
  encrypted_intel?: string;
  from_cache?: boolean;
  error?: string;
}

export interface ArgusIntel {
  virustotal?: ArgusVirusTotalResult;
  abuseipdb?: ArgusAbuseIPDBResult;
  alienvault_otx?: ArgusOTXResult;
  ipinfo?: ArgusIPInfoResult;
  dns?: ArgusDNSResult;
  whois?: ArgusWhoisResult;
  http?: ArgusHTTPResult;
  ssl?: ArgusSSLResult;
  geoip?: ArgusGeoIPResult;
  ip_whois?: ArgusIPWhoisResult;
  reverse_dns?: ArgusReverseDNSResult;
  redirects?: ArgusRedirectResult;
  content?: ArgusContentResult;
  domain?: ArgusDomainResult;
}

export interface ArgusVirusTotalResult {
  detected: boolean;
  positives?: number;
  total?: number;
  scan_date?: string;
  permalink?: string;
  error?: string;
}

export interface ArgusAbuseIPDBResult {
  is_whitelisted?: boolean;
  abuse_confidence_score?: number;
  country_code?: string;
  isp?: string;
  domain?: string;
  total_reports?: number;
  last_reported_at?: string;
  error?: string;
}

export interface ArgusOTXResult {
  pulse_count?: number;
  reputation?: number;
  indicator?: string;
  error?: string;
}

export interface ArgusIPInfoResult {
  ip?: string;
  hostname?: string;
  city?: string;
  region?: string;
  country?: string;
  loc?: string;
  org?: string;
  postal?: string;
  timezone?: string;
  error?: string;
}

export interface ArgusDNSResult {
  a_records?: string[];
  aaaa_records?: string[];
  mx_records?: string[];
  ns_records?: string[];
  txt_records?: string[];
  cname_records?: string[];
  error?: string;
}

export interface ArgusWhoisResult {
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  name_servers?: string[];
  status?: string[];
  domain_name?: string;
  error?: string;
}

export interface ArgusHTTPResult {
  status_code?: number;
  headers?: Record<string, string>;
  server?: string;
  content_type?: string;
  content_length?: number;
  redirect_url?: string;
  error?: string;
}

export interface ArgusSSLResult {
  issuer?: string;
  subject?: string;
  valid_from?: string;
  valid_to?: string;
  serial_number?: string;
  version?: number;
  is_valid?: boolean;
  days_until_expiry?: number;
  error?: string;
}

export interface ArgusGeoIPResult {
  country?: string;
  country_code?: string;
  region?: string;
  city?: string;
  latitude?: number;
  longitude?: number;
  isp?: string;
  org?: string;
  error?: string;
}

export interface ArgusIPWhoisResult {
  asn?: string;
  asn_cidr?: string;
  asn_description?: string;
  asn_country_code?: string;
  network_name?: string;
  network_cidr?: string;
  error?: string;
}

export interface ArgusReverseDNSResult {
  hostname?: string;
  error?: string;
}

export interface ArgusRedirectResult {
  chain?: Array<{
    url: string;
    status_code: number;
    headers?: Record<string, string>;
  }>;
  final_url?: string;
  hop_count?: number;
  error?: string;
}

export interface ArgusContentResult {
  suspicious_patterns?: string[];
  malware_indicators?: string[];
  script_injection?: boolean;
  executable_content?: boolean;
  error?: string;
}

export interface ArgusDomainResult {
  domain?: string;
  tld?: string;
  is_suspicious_tld?: boolean;
  is_url_shortener?: boolean;
  homograph_detected?: boolean;
  punycode_detected?: boolean;
  phishing_keywords?: string[];
  age_days?: number;
  error?: string;
}

export interface ArgusBatchResult {
  results: ArgusScanResult[];
  total: number;
  scanned: number;
  errors: number;
}

export interface ArgusScanHistoryEntry {
  url: string;
  threat_level: string;
  threat_score?: number;
  scanned_at: string;
  from_cache: boolean;
}

export interface ArgusScanHistory {
  entries: ArgusScanHistoryEntry[];
  total: number;
  limit: number;
  offset: number;
}

export interface ArgusSandboxStatus {
  sandbox: boolean;
}

export interface ArgusEncryptResponse {
  encrypted: string;
}

export interface ArgusDecryptResponse {
  decrypted: string;
}

export interface ArgusHealthInfo {
  status: 'running' | 'stopped' | 'starting' | 'error';
  pid: number | null;
  port: number;
  uptimeMs: number;
  lastError: string | null;
}
