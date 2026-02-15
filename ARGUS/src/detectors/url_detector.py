"""
ARGUS Deep URL Intelligence Module
Performs comprehensive OSINT analysis on URLs to determine WHO, WHEN, WHERE.
Fetches WHOIS, DNS, GeoIP, SSL certificates, HTTP headers, redirect chains,
IP ownership, hosting provider, technology fingerprinting, and more.
"""

import re
import ssl
import json
import socket
import urllib.parse
import ipaddress
import logging
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import whois
import dns.resolver
import validators
from bs4 import BeautifulSoup

from src.detectors.threat_intel import ThreatIntelAggregator
from src.detectors.sandbox import IsolationProvider, verify_final_destination
from src.detectors.content_analysis import ContentAnalyzer
from src.detectors.domain_analysis import DomainAnalyzer
from src.core.safety_guard import get_safety_guard, SafetyViolation

logger = logging.getLogger('argus.url_detector')


class URLThreatLevel:
    SAFE = "SAFE"
    LOW = "LOW"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


class URLDetector:
    """
    Deep URL intelligence engine.
    Every scan answers: WHO owns it, WHEN it was created, WHERE it is hosted,
    and HOW it behaves on the network.
    """

    REQUEST_TIMEOUT = 6

    def __init__(self, config: dict):
        self.config = config

        # Max redirect hops from config (WHITECODE default: 5)
        self.MAX_REDIRECTS = config.get('max_redirect_depth', 5)

        self.suspicious_tlds = set(config.get('suspicious_tlds', [
            '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.buzz',
            '.club', '.work', '.date', '.racing', '.win', '.bid',
            '.stream', '.download', '.loan', '.men', '.click', '.link',
            '.info', '.pw', '.cc', '.icu', '.cam', '.rest'
        ]))
        _default_shorteners = [
            r'bit\.ly', r'tinyurl\.com', r't\.co', r'goo\.gl', r'is\.gd',
            r'buff\.ly', r'ow\.ly', r'adf\.ly', r'tiny\.cc', r'rb\.gy',
            r'shorturl\.at', r'cutt\.ly', r'v\.gd', r'qr\.ae',
            r'xini\.eu', r'shorte\.st', r'bc\.vc', r'ouo\.io',
            r'za\.gl', r'clck\.ru', r'tny\.im', r'link\.tl',
            r'soo\.gd', r'u\.to', r's\.id', r'0\.gp',
            r'lnk\.to', r'dub\.sh', r'short\.io', r'rebrand\.ly',
            r'bl\.ink', r'snip\.ly', r'clk\.sh', r'han\.gl',
        ]
        _raw_patterns = config.get('suspicious_patterns', _default_shorteners)
        # Auto-escape plain domain strings from config (e.g. 'bit.ly' -> r'bit\.ly')
        _compiled = []
        self._known_shortener_domains = set()
        for p in _raw_patterns:
            # If pattern has no regex metacharacters (except .), treat as literal domain
            if not any(c in p for c in r'\[](){}*+?|^$') and '.' in p:
                self._known_shortener_domains.add(p.lower())
                _compiled.append(re.compile(re.escape(p), re.IGNORECASE))
            else:
                # Already a regex pattern (has backslash escapes etc.)
                clean = p.replace(r'\.', '.').replace('\\', '').lower()
                self._known_shortener_domains.add(clean)
                _compiled.append(re.compile(p, re.IGNORECASE))
        self.suspicious_patterns = _compiled
        self.phishing_keywords = [
            re.compile(kw, re.IGNORECASE) for kw in config.get('phishing_keywords', [
                'login', 'signin', 'verify', 'account', 'secure', 'update',
                'confirm', 'password', 'credential', 'suspend', 'unusual',
                'authenticate', 'wallet', 'banking', 'paypal', 'ebay',
                'amazon', 'microsoft', 'apple', 'google', 'facebook',
                'unlock', 'expire',
            ])
        ]
        self.max_url_length = config.get('max_url_length', 2048)

        # Feature flags from config (all forced true by WHITECODE)
        self._punycode_check = config.get('punycode_check', True)
        self._homograph_detection = config.get('homograph_detection', True)
        self._content_type_validation = config.get('content_type_validation', True)

        self.malicious_domains = {
            'malware-example.com', 'phishing-site.net', 'scam-domain.org'
        }

        self._content_analyzer = ContentAnalyzer()
        self._domain_analyzer = DomainAnalyzer()

        # SafetyGuard — pass url_fetch config from config.yaml
        url_fetch_cfg = config.get('url_fetch', {})
        self._safety = get_safety_guard(config=url_fetch_cfg)

        # Sandbox isolation layer — env-controlled, defaults to true if unset
        import os
        sandbox_cfg = config.get('sandbox', {})
        sandbox_val = sandbox_cfg.get('enabled', '${ARGUS_SANDBOX_MODE}')
        if isinstance(sandbox_val, str) and sandbox_val.startswith('${'):
            sandbox_val = os.environ.get(sandbox_val[2:-1], 'true')
        self.sandbox = IsolationProvider(
            enabled=str(sandbox_val).lower() in ('true', '1', 'yes'))

        # Network objects — created lazily, only when sandbox is OFF
        self._session = None          # created on first live scan
        self.threat_intel = None      # created on first live scan
        self._threat_intel_enabled = config.get('threat_intel', {}).get('enabled', True)
        self._ti_config = config.get('threat_intel', {})

        if not self.sandbox.is_active:
            self._init_network()
        else:
            logger.info('Sandbox ON — skipping network initialisation (zero connections)')

    def _init_network(self):
        """Lazily create requests.Session and ThreatIntelAggregator.
        Called only when a live (non-sandbox) scan is needed."""
        if self._session is not None:
            return  # already initialised
        import os
        self._session = requests.Session()
        self._session.headers.update({
            'User-Agent': 'ARGUS/1.0 Security Scanner (https://github.com/argus-security)'
        })
        ti = self._ti_config
        def _key(cfg_key, env_key):
            v = ti.get(cfg_key, '')
            if v and v.startswith('${') and v.endswith('}'):
                return os.environ.get(v[2:-1], '')
            return os.environ.get(env_key, v or '')

        self.threat_intel = ThreatIntelAggregator(
            vt_key=_key('virustotal_api_key', 'ARGUS_VIRUSTOTAL_KEY'),
            abuseipdb_key=_key('abuseipdb_api_key', 'ARGUS_ABUSEIPDB_KEY'),
            otx_key=_key('alienvault_otx_api_key', 'ARGUS_OTX_KEY'),
            ipinfo_token=_key('ipinfo_token', 'ARGUS_IPINFO_TOKEN'),
        )
        logger.info('Network layer initialised (session + threat intel APIs)')

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Ensure URL has a scheme. Bare domains like 'google.com' get http:// prepended."""
        url = url.strip()
        if not url:
            return url
        # Already has a scheme (http://, https://, ftp://, file://, data:, etc.)
        if '://' in url or url.startswith('data:'):
            return url
        # Strip leading www. noise for scheme detection but keep it in the URL
        # e.g. "www.google.com" -> "http://www.google.com"
        return 'http://' + url

    def analyze_url(self, url: str) -> Dict:
        """Full OSINT analysis of a URL — returns rich intelligence data."""
        if not url or not isinstance(url, str):
            return self._create_result(url, URLThreatLevel.UNKNOWN, "Invalid URL format")

        # Auto-prepend scheme for bare domains (e.g. "google.com" -> "http://google.com")
        url = self._normalize_url(url)

        try:
            # ── SAFETY GATE: block dangerous targets before ANY network I/O ──
            safe, block_reason = self._safety.validate_scan_target(url)
            if not safe:
                logger.warning('SAFETY BLOCKED scan of %s: %s', url, block_reason)
                parsed = urllib.parse.urlparse(url)
                domain = (parsed.netloc or '').lower().split(':')[0]
                return {
                    'url': url,
                    'domain': domain,
                    'threat_level': URLThreatLevel.CRITICAL,
                    'threat_score': 20,
                    'reasons': [f'SAFETY BLOCK: {block_reason}'],
                    'intel': {'safety_blocked': True, 'block_reason': block_reason},
                    'blocked': True,
                    'safety_block': {'reason': block_reason, 'url': url},
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }

            if not validators.url(url):
                return self._create_result(url, URLThreatLevel.UNKNOWN, "Invalid URL structure")

            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            if ':' in domain:
                domain = domain.split(':')[0]

            threat_score = 0
            reasons = []

            # --- Phase 1: Static pattern analysis ---
            threat_score += self._check_url_length(url, reasons)
            threat_score += self._check_domain_reputation(domain, reasons)
            threat_score += self._check_tld(domain, reasons)
            threat_score += self._check_ip_address(domain, reasons)
            threat_score += self._check_suspicious_patterns(url, reasons)
            threat_score += self._check_phishing_indicators(url, parsed, reasons)
            threat_score += self._check_url_structure(url, parsed, reasons)
            threat_score += self._check_query_params(parsed, reasons)

            # Punycode / IDN homograph detection
            if self._punycode_check and domain.startswith('xn--'):
                threat_score += 3
                reasons.append(f'Punycode/IDN domain detected: {domain}')
                try:
                    decoded = domain.encode('ascii').decode('idna')
                    reasons.append(f'IDN decoded: {decoded}')
                except Exception:
                    pass
            if self._homograph_detection:
                threat_score += self._check_homograph(domain, reasons)

            # --- Phase 2: Deep OSINT (always run for maximum intel) ---
            intel = self._gather_intelligence(url, domain, parsed)

            # --- KILLSWITCH: instant CRITICAL if sandbox blocked this URL ---
            ks = intel.get('killswitch')
            if ks:
                reasons.insert(0, f"KILLSWITCH BLOCKED: {ks.get('reason', 'malicious destination')}")
                return {
                    'url': url,
                    'domain': domain,
                    'threat_level': URLThreatLevel.CRITICAL,
                    'threat_score': max(threat_score, 20),
                    'reasons': reasons,
                    'intel': intel,
                    'blocked': True,
                    'killswitch': ks,
                    'timestamp': datetime.now(timezone.utc).isoformat(),
                }

            # --- Phase 3: Score from intelligence ---
            threat_score += self._score_from_intel(intel, reasons)

            threat_level = self._determine_threat_level(threat_score)

            result = {
                'url': url,
                'domain': domain,
                'threat_level': threat_level,
                'threat_score': threat_score,
                'reasons': reasons,
                'intel': intel,
                'timestamp': datetime.now(timezone.utc).isoformat(),
            }

            # Mark as blocked if CRITICAL (redirect SSRF, malware body, etc.)
            if threat_level == URLThreatLevel.CRITICAL:
                result['blocked'] = True
                http_data = intel.get('http', {})
                if isinstance(http_data, dict) and http_data.get('blocked_redirect'):
                    result['safety_block'] = {
                        'reason': f"Redirect to blocked target: {http_data['blocked_redirect']}",
                        'url': url,
                    }

            return result

        except Exception as e:
            logger.exception("Analysis error for %s", url)
            return self._create_result(url, URLThreatLevel.UNKNOWN, f"Analysis error: {str(e)}")

    def batch_analyze(self, urls: List[str]) -> List[Dict]:
        """Analyze multiple URLs in parallel."""
        results = []
        with ThreadPoolExecutor(max_workers=5) as pool:
            futures = {pool.submit(self.analyze_url, u): u for u in urls}
            for future in as_completed(futures):
                results.append(future.result())
        return results

    # ------------------------------------------------------------------
    # INTELLIGENCE GATHERING (Phase 2)
    # ------------------------------------------------------------------

    def _gather_intelligence(self, url: str, domain: str, parsed) -> Dict:
        """Run all intelligence modules in parallel where possible.
        When sandbox mode is active, every call is intercepted by the
        IsolationProvider — no real HTTP traffic leaves the machine."""
        intel: Dict[str, Any] = {'_input_url': url}

        # ── Sandbox path (zero network I/O) ──
        if self.sandbox.is_active:
            logger.info('SANDBOX MODE — intercepting all intelligence for %s', url)
            intel['dns'] = self.sandbox.intercept_dns(domain)
            intel['whois'] = self.sandbox.intercept_whois(domain)
            intel['http'] = self.sandbox.intercept_http(url)
            intel['ssl'] = self.sandbox.intercept_ssl(
                domain, parsed.port or (443 if parsed.scheme == 'https' else None))

            resolved_ips = intel['dns'].get('A', [])
            if resolved_ips:
                primary_ip = resolved_ips[0]
                intel['geoip'] = self.sandbox.intercept_geoip(primary_ip)
                intel['ip_whois'] = self.sandbox.intercept_ip_whois(primary_ip)
                intel['reverse_dns'] = self.sandbox.intercept_reverse_dns(primary_ip)
                intel['resolved_ips'] = resolved_ips

            intel['redirect_chain'] = self.sandbox.intercept_redirect_chain(url)

            # ── KILLSWITCH: if redirect chain triggered a block, abort now ──
            ks = intel['redirect_chain'].get('killswitch')
            if ks:
                logger.critical('KILLSWITCH BLOCKED %s — %s', url, ks.get('reason'))
                intel['killswitch'] = ks
                intel['final_destination'] = {
                    'url': ks.get('url', url),
                    'domain': ks.get('domain', domain),
                    'risk_score': ks.get('risk_score', 100),
                    'verdict': 'DANGEROUS',
                    'color': 'red',
                    'in_blacklist': True,
                    'sandbox': True,
                    'blocked': True,
                }
                intel['sandbox_active'] = True
                return intel

            intel['url_params'] = self._intel_url_params(parsed)
            intel['content_analysis'] = self.sandbox.intercept_content_analysis(url, domain)

            primary_ip = resolved_ips[0] if resolved_ips else None
            intel['threat_intel'] = self.sandbox.intercept_threat_intel(
                url, domain, primary_ip)

            # Domain analysis (works offline — no network needed)
            try:
                whois_data = intel.get('whois') if isinstance(intel.get('whois'), dict) else None
                intel['domain_analysis'] = self._domain_analyzer.analyze(domain, whois_data)
            except Exception as e:
                intel['domain_analysis'] = {'error': str(e)}

            # Safety card for the final destination
            final_url = intel['redirect_chain'].get('final_url', url)
            intel['final_destination'] = verify_final_destination(
                final_url, sandbox_mode=True)

            intel['sandbox_active'] = True
            return intel

        # ── Live path (real network I/O) ──
        self._init_network()  # lazy init — creates session + threat intel on first live scan

        # Phase 1: Core intel — all in parallel (DNS, WHOIS, HTTP, SSL, redirect chain)
        futures = {}
        pool = ThreadPoolExecutor(max_workers=8)
        try:
            futures = {
                pool.submit(self._intel_dns, domain): 'dns',
                pool.submit(self._intel_whois, domain): 'whois',
                pool.submit(self._intel_http, url): 'http',
                pool.submit(self._intel_ssl, domain, parsed.port or (443 if parsed.scheme == 'https' else None)): 'ssl',
                pool.submit(self._intel_redirect_chain, url): 'redirect_chain',
            }
            try:
                for future in as_completed(futures, timeout=20):
                    key = futures[future]
                    try:
                        intel[key] = future.result()
                    except Exception as e:
                        intel[key] = {'error': str(e)}
            except TimeoutError:
                logger.warning('Phase 1 timed out after 20s — continuing with partial results')
        finally:
            pool.shutdown(wait=False)

        for future, key in futures.items():
            if key not in intel:
                intel[key] = {'error': 'Timed out'}

        # Phase 2: IP-dependent intel + threat intel — all in parallel
        resolved_ips = []
        dns_data = intel.get('dns', {})
        if isinstance(dns_data, dict):
            resolved_ips = dns_data.get('A', []) + dns_data.get('AAAA', [])

        phase2_futures = {}
        pool2 = ThreadPoolExecutor(max_workers=6)
        try:
            if resolved_ips:
                primary_ip = resolved_ips[0]
                phase2_futures[pool2.submit(self._intel_geoip, primary_ip)] = 'geoip'
                phase2_futures[pool2.submit(self._intel_ip_whois, primary_ip)] = 'ip_whois'
                phase2_futures[pool2.submit(self._intel_reverse_dns, primary_ip)] = 'reverse_dns'
                intel['resolved_ips'] = resolved_ips
            else:
                primary_ip = None

            if self._threat_intel_enabled and self.threat_intel:
                phase2_futures[pool2.submit(
                    self.threat_intel.full_analysis, url, domain, primary_ip
                )] = 'threat_intel'

            if phase2_futures:
                try:
                    for future in as_completed(phase2_futures, timeout=15):
                        key = phase2_futures[future]
                        try:
                            intel[key] = future.result()
                        except Exception as e:
                            intel[key] = {'error': str(e)}
                except TimeoutError:
                    logger.warning('Phase 2 timed out after 15s — continuing with partial results')
        finally:
            pool2.shutdown(wait=False)

        for future, key in phase2_futures.items():
            if key not in intel:
                intel[key] = {'error': 'Timed out'}

        # Phase 3: Offline analysis (instant — no network)
        intel['url_params'] = self._intel_url_params(parsed)

        http_data = intel.get('http', {})
        if isinstance(http_data, dict) and not http_data.get('error'):
            try:
                body = http_data.get('_body_snippet', '')
                if body:
                    intel['content_analysis'] = self._content_analyzer.analyze(body, url)
            except Exception as e:
                intel['content_analysis'] = {'error': str(e)}

        try:
            whois_data = intel.get('whois') if isinstance(intel.get('whois'), dict) else None
            intel['domain_analysis'] = self._domain_analyzer.analyze(domain, whois_data)
        except Exception as e:
            intel['domain_analysis'] = {'error': str(e)}

        # Safety card for the final destination
        redir = intel.get('redirect_chain', {})
        final_url = redir.get('final_url', url)
        intel['final_destination'] = verify_final_destination(
            final_url, sandbox_mode=False)

        intel['sandbox_active'] = False
        return intel

    # --- DNS Intelligence ---
    def _intel_dns(self, domain: str) -> Dict:
        """Comprehensive DNS record enumeration with timeout-capped resolver."""
        records: Dict[str, Any] = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'CAA']

        resolver = dns.resolver.Resolver()
        resolver.timeout = 4       # per-query timeout
        resolver.lifetime = 10     # total lifetime for all queries

        for rtype in record_types:
            try:
                answers = resolver.resolve(domain, rtype)
                if rtype == 'SOA':
                    soa = answers[0]
                    records[rtype] = {
                        'mname': str(soa.mname),
                        'rname': str(soa.rname),
                        'serial': soa.serial,
                        'refresh': soa.refresh,
                        'retry': soa.retry,
                        'expire': soa.expire,
                        'minimum': soa.minimum,
                    }
                elif rtype == 'MX':
                    records[rtype] = [
                        {'priority': r.preference, 'exchange': str(r.exchange)}
                        for r in answers
                    ]
                else:
                    records[rtype] = [str(r) for r in answers]
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                    dns.resolver.NoNameservers, dns.resolver.Timeout):
                pass
            except Exception:
                pass

        # SPF / DMARC / DKIM discovery from TXT
        txt_records = records.get('TXT', [])
        records['spf'] = [t for t in txt_records if 'v=spf1' in t.lower()]
        records['dmarc'] = self._dns_lookup(f'_dmarc.{domain}', 'TXT')
        records['has_dnssec'] = self._check_dnssec(domain)

        return records

    def _dns_lookup(self, name: str, rtype: str) -> List[str]:
        try:
            answers = dns.resolver.resolve(name, rtype)
            return [str(r) for r in answers]
        except Exception:
            return []

    def _check_dnssec(self, domain: str) -> bool:
        try:
            dns.resolver.resolve(domain, 'DNSKEY')
            return True
        except Exception:
            return False

    # --- WHOIS Intelligence ---
    def _intel_whois(self, domain: str) -> Dict:
        """Rich WHOIS data extraction with hard timeout."""
        import threading
        result_box = [None]
        exc_box = [None]
        def _do():
            try:
                result_box[0] = whois.whois(domain)
            except Exception as e:
                exc_box[0] = e
        t = threading.Thread(target=_do, daemon=True)
        t.start()
        t.join(timeout=8)
        if t.is_alive():
            return {'error': 'WHOIS lookup timed out (8s)'}
        if exc_box[0]:
            return {'error': f'WHOIS lookup failed: {exc_box[0]}'}
        w = result_box[0]
        if w is None:
            return {'error': 'WHOIS returned no data'}
        try:
            w  # already resolved
            result: Dict[str, Any] = {}

            def safe_date(d):
                if d is None:
                    return None
                if isinstance(d, list):
                    d = d[0]
                if isinstance(d, datetime):
                    return d.isoformat()
                return str(d)

            def safe_str(v):
                if v is None:
                    return None
                if isinstance(v, list):
                    return [str(x) for x in v]
                return str(v)

            result['registrar'] = safe_str(w.registrar)
            result['registrant_org'] = safe_str(getattr(w, 'org', None))
            result['registrant_country'] = safe_str(w.country)
            result['registrant_state'] = safe_str(getattr(w, 'state', None))
            result['registrant_city'] = safe_str(getattr(w, 'city', None))
            result['registrant_name'] = safe_str(getattr(w, 'name', None))
            result['registrant_email'] = safe_str(getattr(w, 'emails', None))
            result['creation_date'] = safe_date(w.creation_date)
            result['expiration_date'] = safe_date(w.expiration_date)
            result['updated_date'] = safe_date(w.updated_date)
            result['name_servers'] = safe_str(w.name_servers)
            result['status'] = safe_str(w.status)
            result['dnssec'] = safe_str(getattr(w, 'dnssec', None))

            # Domain age calculation
            created = w.creation_date
            if isinstance(created, list):
                created = created[0]
            if isinstance(created, str):
                try:
                    created = datetime.fromisoformat(created.replace('Z', '+00:00'))
                except Exception:
                    created = None
            if isinstance(created, datetime):
                if created.tzinfo is None:
                    created = created.replace(tzinfo=timezone.utc)
                age_days = (datetime.now(timezone.utc) - created).days
                result['domain_age_days'] = age_days
                if age_days < 30:
                    result['newly_registered'] = True
                elif age_days < 180:
                    result['young_domain'] = True

            return result

        except Exception as e:
            return {'error': f'WHOIS lookup failed: {str(e)}'}

    # --- HTTP Intelligence ---
    def _intel_http(self, url: str) -> Dict:
        """Fetch HTTP headers, server info, cookies, security headers.
        Manually follows redirects with SafetyGuard validation at EACH hop
        BEFORE connecting (prevents SSRF via open redirects)."""
        result: Dict[str, Any] = {}
        try:
            current_url = url
            max_hops = self._safety.max_redirect_hops
            hop_chain = [current_url]

            for hop in range(max_hops + 1):
                # Validate BEFORE connecting (Steps 1-4 at each hop)
                if hop > 0:
                    hop_safe, hop_reason = self._safety.validate_redirect_target(current_url)
                    if not hop_safe:
                        result['error'] = f'Redirect hop {hop} blocked: {hop_reason}'
                        result['blocked_redirect'] = current_url
                        result['redirect_chain'] = hop_chain
                        logger.warning('Redirect blocked at hop %d: %s -> %s',
                                       hop, hop_chain[-2] if len(hop_chain) > 1 else url, current_url)
                        return result

                resp = self._session.get(current_url, timeout=self.REQUEST_TIMEOUT,
                                         allow_redirects=False, verify=False,
                                         stream=True)

                # If redirect, extract Location and loop
                if resp.is_redirect or resp.is_permanent_redirect:
                    location = resp.headers.get('Location', '')
                    resp.close()
                    if not location:
                        break
                    # Resolve relative redirects
                    current_url = urllib.parse.urljoin(current_url, location)
                    hop_chain.append(current_url)
                    if hop == max_hops:
                        result['error'] = f'Too many redirects ({max_hops} hops)'
                        result['redirect_chain'] = hop_chain
                        return result
                    continue
                else:
                    break  # not a redirect — process the response

            result['status_code'] = resp.status_code
            result['final_url'] = resp.url
            result['redirect_chain'] = hop_chain if len(hop_chain) > 1 else None
            result['response_time_ms'] = int(resp.elapsed.total_seconds() * 1000)

            headers = dict(resp.headers)
            result['server'] = headers.get('Server', 'Unknown')
            result['powered_by'] = headers.get('X-Powered-By', None)
            result['content_type'] = headers.get('Content-Type', None)

            # Step 6: Content-Type validation (block dangerous binary types)
            ct_safe, ct_reason = self._safety.validate_content_type(
                headers.get('Content-Type', ''))
            if not ct_safe:
                result['content_type_blocked'] = ct_reason
                logger.warning('Content-Type blocked for %s: %s', url, ct_reason)
                resp.close()
                return result

            # Security headers audit
            security_headers = {}
            sec_header_names = [
                'Strict-Transport-Security', 'Content-Security-Policy',
                'X-Content-Type-Options', 'X-Frame-Options',
                'X-XSS-Protection', 'Referrer-Policy',
                'Permissions-Policy', 'Cross-Origin-Opener-Policy',
                'Cross-Origin-Resource-Policy', 'Cross-Origin-Embedder-Policy',
            ]
            for h in sec_header_names:
                val = headers.get(h)
                security_headers[h] = val if val else 'MISSING'
            result['security_headers'] = security_headers

            missing_count = sum(1 for v in security_headers.values() if v == 'MISSING')
            result['security_header_score'] = f"{len(sec_header_names) - missing_count}/{len(sec_header_names)}"

            # Cookies analysis
            cookies = []
            for cookie in resp.cookies:
                cookies.append({
                    'name': cookie.name,
                    'domain': cookie.domain,
                    'path': cookie.path,
                    'secure': cookie.secure,
                    'httponly': cookie.has_nonstandard_attr('httponly') or cookie.has_nonstandard_attr('HttpOnly'),
                    'expires': str(cookie.expires) if cookie.expires else None,
                })
            result['cookies'] = cookies

            # Safe body read with config-driven size cap
            body_text = self._safety.safe_read_body(resp)
            result['technologies'] = self._fingerprint_technologies(headers, body_text[:5000])

            # Step 7: Post-fetch body safety scan
            body_safe, body_reason = self._safety.scan_body_safety(body_text, url)
            if not body_safe:
                result['body_blocked'] = body_reason
                logger.warning('POST-FETCH body blocked for %s: %s', url, body_reason)

            # Store body snippet for content analysis (not sent to UI)
            result['_body_snippet'] = body_text[:50000]

            # All response headers (for full transparency)
            result['all_headers'] = headers

        except requests.exceptions.SSLError as e:
            result['error'] = f'SSL Error: {str(e)}'
            result['ssl_error'] = True
        except requests.exceptions.ConnectionError as e:
            result['error'] = f'Connection failed: {str(e)}'
        except requests.exceptions.Timeout:
            result['error'] = 'Request timed out'
        except Exception as e:
            result['error'] = str(e)

        return result

    # --- SSL Certificate Intelligence ---
    def _intel_ssl(self, domain: str, port: Optional[int]) -> Dict:
        """Extract SSL certificate details using cryptography.x509 for reliable parsing."""
        if port is None:
            port = 443
        result: Dict[str, Any] = {}
        try:
            from cryptography import x509
            from cryptography.hazmat.backends import default_backend
            from cryptography.x509.oid import NameOID, ExtensionOID

            # Safety: resolve domain first and validate the IP before connecting
            try:
                infos = socket.getaddrinfo(domain, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
                if infos:
                    ip_str = infos[0][4][0]
                    ip_safe, ip_reason = self._safety.validate_ip(ip_str)
                    if not ip_safe:
                        return {'error': f'SSL blocked: {ip_reason}'}
            except socket.gaierror as e:
                return {'error': f'DNS resolution failed for SSL: {e}'}

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((domain, port), timeout=self.REQUEST_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=True)
                    protocol_version = ssock.version()

            if not der_cert:
                result['error'] = 'No certificate returned'
                return result

            cert = x509.load_der_x509_certificate(der_cert, default_backend())

            # Subject
            subject_parts = {}
            for attr in cert.subject:
                subject_parts[attr.oid._name] = attr.value
            result['subject'] = subject_parts

            # Issuer
            issuer_parts = {}
            for attr in cert.issuer:
                issuer_parts[attr.oid._name] = attr.value
            result['issuer'] = issuer_parts

            # Validity
            not_before = cert.not_valid_before
            not_after = cert.not_valid_after
            result['not_before'] = not_before.strftime('%Y-%m-%d %H:%M:%S UTC')
            result['not_after'] = not_after.strftime('%Y-%m-%d %H:%M:%S UTC')
            result['serial_number'] = format(cert.serial_number, 'X')
            result['version'] = cert.version.name
            result['signature_algorithm'] = cert.signature_algorithm_oid._name
            result['tls_version'] = protocol_version

            # Days until expiry
            now = datetime.now(timezone.utc)
            not_after_utc = not_after.replace(tzinfo=timezone.utc) if not_after.tzinfo is None else not_after
            days_left = (not_after_utc - now).days
            result['days_until_expiry'] = days_left
            if days_left < 0:
                result['expired'] = True
            elif days_left < 30:
                result['expiring_soon'] = True

            # Subject Alternative Names
            try:
                san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                sans = []
                for name in san_ext.value.get_values_for_type(x509.DNSName):
                    sans.append({'type': 'DNS', 'value': name})
                for name in san_ext.value.get_values_for_type(x509.IPAddress):
                    sans.append({'type': 'IP', 'value': str(name)})
                result['subject_alt_names'] = sans
            except x509.ExtensionNotFound:
                result['subject_alt_names'] = []

            # Authority Information Access (OCSP, CA Issuers)
            try:
                aia_ext = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
                ocsp_urls = []
                ca_issuers = []
                for desc in aia_ext.value:
                    if desc.access_method == x509.oid.AuthorityInformationAccessOID.OCSP:
                        ocsp_urls.append(desc.access_location.value)
                    elif desc.access_method == x509.oid.AuthorityInformationAccessOID.CA_ISSUERS:
                        ca_issuers.append(desc.access_location.value)
                result['ocsp'] = ocsp_urls
                result['ca_issuers'] = ca_issuers
            except x509.ExtensionNotFound:
                result['ocsp'] = []
                result['ca_issuers'] = []

            # CRL Distribution Points
            try:
                crl_ext = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
                crl_urls = []
                for dp in crl_ext.value:
                    if dp.full_name:
                        for name in dp.full_name:
                            crl_urls.append(name.value)
                result['crl'] = crl_urls
            except x509.ExtensionNotFound:
                result['crl'] = []

            # Key Usage
            try:
                ku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
                ku = ku_ext.value
                usages = []
                for usage_name in ['digital_signature', 'key_encipherment', 'content_commitment',
                                   'data_encipherment', 'key_agreement', 'key_cert_sign',
                                   'crl_sign']:
                    try:
                        if getattr(ku, usage_name):
                            usages.append(usage_name.replace('_', ' ').title())
                    except ValueError:
                        pass
                result['key_usage'] = usages
            except x509.ExtensionNotFound:
                result['key_usage'] = []

            # Extended Key Usage
            try:
                eku_ext = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
                result['extended_key_usage'] = [eku.dotted_string for eku in eku_ext.value]
            except x509.ExtensionNotFound:
                result['extended_key_usage'] = []

        except ssl.SSLError as e:
            result['error'] = f'SSL error: {str(e)}'
        except socket.timeout:
            result['error'] = 'SSL connection timed out'
        except (ConnectionRefusedError, OSError) as e:
            result['error'] = f'Connection refused: {str(e)}'
        except Exception as e:
            result['error'] = f'SSL analysis failed: {str(e)}'

        return result

    # --- GeoIP Intelligence ---
    def _intel_geoip(self, ip: str) -> Dict:
        """GeoIP lookup using free ip-api.com service."""
        try:
            resp = self._session.get(
                f'http://ip-api.com/json/{ip}?fields=status,message,continent,continentCode,'
                f'country,countryCode,region,regionName,city,zip,lat,lon,timezone,'
                f'isp,org,as,asname,reverse,mobile,proxy,hosting,query',
                timeout=self.REQUEST_TIMEOUT
            )
            data = resp.json()
            if data.get('status') == 'success':
                return {
                    'ip': ip,
                    'continent': data.get('continent'),
                    'country': data.get('country'),
                    'country_code': data.get('countryCode'),
                    'region': data.get('regionName'),
                    'city': data.get('city'),
                    'zip': data.get('zip'),
                    'latitude': data.get('lat'),
                    'longitude': data.get('lon'),
                    'timezone': data.get('timezone'),
                    'isp': data.get('isp'),
                    'org': data.get('org'),
                    'as_number': data.get('as'),
                    'as_name': data.get('asname'),
                    'reverse_dns': data.get('reverse'),
                    'is_mobile': data.get('mobile', False),
                    'is_proxy': data.get('proxy', False),
                    'is_hosting': data.get('hosting', False),
                }
            return {'error': data.get('message', 'GeoIP lookup failed')}
        except Exception as e:
            return {'error': str(e)}

    # --- IP WHOIS Intelligence ---
    def _intel_ip_whois(self, ip: str) -> Dict:
        """IP WHOIS lookup for network ownership details."""
        try:
            from ipwhois import IPWhois
            obj = IPWhois(ip)
            rdap = obj.lookup_rdap(depth=1)
            return {
                'asn': rdap.get('asn'),
                'asn_cidr': rdap.get('asn_cidr'),
                'asn_country': rdap.get('asn_country_code'),
                'asn_description': rdap.get('asn_description'),
                'asn_registry': rdap.get('asn_registry'),
                'network_name': rdap.get('network', {}).get('name'),
                'network_cidr': rdap.get('network', {}).get('cidr'),
                'network_country': rdap.get('network', {}).get('country'),
                'network_start': rdap.get('network', {}).get('start_address'),
                'network_end': rdap.get('network', {}).get('end_address'),
            }
        except Exception as e:
            return {'error': str(e)}

    # --- Reverse DNS ---
    def _intel_reverse_dns(self, ip: str) -> Dict:
        """Reverse DNS lookup."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return {'ip': ip, 'hostname': hostname}
        except socket.herror:
            return {'ip': ip, 'hostname': None}
        except Exception as e:
            return {'error': str(e)}

    # --- Redirect Chain ---
    def _intel_redirect_chain(self, url: str) -> Dict:
        """Trace the full redirect chain, recording each hop."""
        chain = []
        current_url = url
        visited = set()

        try:
            for i in range(self.MAX_REDIRECTS):
                if current_url in visited:
                    chain.append({'hop': i + 1, 'url': current_url, 'note': 'REDIRECT LOOP DETECTED'})
                    break
                visited.add(current_url)

                resp = self._session.get(
                    current_url, timeout=4,
                    allow_redirects=False, verify=False
                )
                hop = {
                    'hop': i + 1,
                    'url': current_url,
                    'status_code': resp.status_code,
                    'server': resp.headers.get('Server', 'Unknown'),
                }

                if resp.is_redirect or resp.is_permanent_redirect:
                    next_url = resp.headers.get('Location', '')
                    if next_url and not next_url.startswith('http'):
                        next_url = urllib.parse.urljoin(current_url, next_url)
                    # Safety: validate redirect target before following
                    redir_safe, redir_reason = self._safety.validate_redirect_target(next_url)
                    if not redir_safe:
                        hop['redirects_to'] = next_url
                        hop['note'] = f'BLOCKED: {redir_reason}'
                        chain.append(hop)
                        break
                    hop['redirects_to'] = next_url
                    chain.append(hop)
                    current_url = next_url
                else:
                    chain.append(hop)
                    break

        except Exception as e:
            chain.append({'error': str(e)})

        return {
            'total_hops': len(chain),
            'chain': chain,
            'final_url': current_url,
            'has_redirects': len(chain) > 1,
        }

    # --- URL Parameter Analysis ---
    def _intel_url_params(self, parsed) -> Dict:
        """Decode and analyze all URL query parameters."""
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
        decoded_params = {}
        suspicious_params = []

        tracking_keys = {
            'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
            'fbclid', 'gclid', 'msclkid', 'dclid', 'mc_cid', 'mc_eid',
            'ref', 'affiliate', 'source', 'campaign'
        }
        sensitive_keys = {
            'token', 'key', 'api_key', 'apikey', 'secret', 'password', 'pass',
            'auth', 'session', 'sid', 'ssid', 'credential', 'access_token'
        }

        tracking_found = []
        sensitive_found = []

        for key, values in params.items():
            val = values[0] if len(values) == 1 else values
            decoded_params[key] = val

            key_lower = key.lower()
            if key_lower in tracking_keys:
                tracking_found.append(key)
            if key_lower in sensitive_keys:
                sensitive_found.append(key)

            # Check for encoded URLs in parameter values
            str_val = str(val)
            if re.match(r'https?://', str_val) or re.match(r'https?%3A', str_val, re.IGNORECASE):
                suspicious_params.append({
                    'param': key,
                    'reason': 'Contains embedded URL',
                    'value_preview': str_val[:100]
                })

        return {
            'total_params': len(params),
            'params': decoded_params,
            'tracking_params': tracking_found,
            'sensitive_params': sensitive_found,
            'suspicious_params': suspicious_params,
            'has_tracking': len(tracking_found) > 0,
            'has_sensitive': len(sensitive_found) > 0,
        }

    # --- Technology Fingerprinting ---
    def _fingerprint_technologies(self, headers: Dict, body_snippet: str) -> List[str]:
        """Identify technologies from HTTP headers and HTML content."""
        techs = []
        server = headers.get('Server', '').lower()
        powered = headers.get('X-Powered-By', '').lower()
        all_headers = ' '.join(f'{k}: {v}' for k, v in headers.items()).lower()
        body_lower = body_snippet.lower()

        fingerprints = {
            'Apache': lambda: 'apache' in server,
            'Nginx': lambda: 'nginx' in server,
            'IIS': lambda: 'iis' in server or 'microsoft' in server,
            'Cloudflare': lambda: 'cloudflare' in server or 'cf-ray' in all_headers,
            'AWS CloudFront': lambda: 'cloudfront' in server or 'x-amz' in all_headers,
            'Akamai': lambda: 'akamai' in all_headers or 'x-akamai' in all_headers,
            'Fastly': lambda: 'fastly' in all_headers,
            'Varnish': lambda: 'varnish' in all_headers or 'x-varnish' in all_headers,
            'PHP': lambda: 'php' in powered,
            'ASP.NET': lambda: 'asp.net' in powered or 'x-aspnet' in all_headers,
            'Node.js': lambda: 'express' in powered or 'node' in powered,
            'Python/Django': lambda: 'django' in all_headers or 'csrftoken' in all_headers,
            'Python/Flask': lambda: 'werkzeug' in server or 'flask' in all_headers,
            'WordPress': lambda: 'wp-content' in body_lower or 'wordpress' in body_lower,
            'jQuery': lambda: 'jquery' in body_lower,
            'React': lambda: 'react' in body_lower or '__next' in body_lower,
            'Google Analytics': lambda: 'google-analytics' in body_lower or 'gtag' in body_lower,
            'Google Tag Manager': lambda: 'googletagmanager' in body_lower,
            'Facebook Pixel': lambda: 'fbevents' in body_lower or 'facebook.net/en_US/fbevents' in body_lower,
            'reCAPTCHA': lambda: 'recaptcha' in body_lower,
            'Cloudflare Turnstile': lambda: 'challenges.cloudflare.com' in body_lower,
        }

        for tech, check in fingerprints.items():
            try:
                if check():
                    techs.append(tech)
            except Exception:
                pass

        return techs

    # ------------------------------------------------------------------
    # STATIC CHECKS (Phase 1)
    # ------------------------------------------------------------------

    def _check_url_length(self, url: str, reasons: List[str]) -> int:
        if len(url) > self.max_url_length:
            reasons.append(f"URL length ({len(url)}) exceeds threshold ({self.max_url_length})")
            return 3
        elif len(url) > self.max_url_length * 0.5:
            reasons.append(f"Unusually long URL ({len(url)} chars)")
            return 1
        return 0

    def _check_domain_reputation(self, domain: str, reasons: List[str]) -> int:
        if domain in self.malicious_domains:
            reasons.append("Domain found in malicious database")
            return 10
        return 0

    def _check_tld(self, domain: str, reasons: List[str]) -> int:
        if '.' in domain:
            tld = '.' + domain.split('.')[-1]
            if tld in self.suspicious_tlds:
                reasons.append(f"Suspicious TLD: {tld}")
                return 2
        return 0

    def _check_ip_address(self, domain: str, reasons: List[str]) -> int:
        try:
            ipaddress.ip_address(domain)
            reasons.append("Domain uses raw IP address instead of hostname")
            return 3
        except ValueError:
            pass
        return 0

    def _check_suspicious_patterns(self, url: str, reasons: List[str]) -> int:
        score = 0
        for pattern in self.suspicious_patterns:
            if pattern.search(url):
                reasons.append(f"URL shortener / suspicious pattern: {pattern.pattern}")
                score += 3
                return score  # one match is enough

        # Heuristic shortener detection: short domain + short/encoded path
        try:
            parsed = urllib.parse.urlparse(url)
            host = (parsed.hostname or '').lower()
            path = parsed.path.rstrip('/')
            parts = host.split('.')
            # Strip www
            if parts and parts[0] == 'www':
                parts = parts[1:]
            base_domain = '.'.join(parts)

            # Exact match against known shortener domains
            if base_domain in self._known_shortener_domains:
                reasons.append(f"Known URL shortener domain: {base_domain}")
                score += 3
                return score

            # Heuristic: domain <= 8 chars (e.g. xini.eu, t.co, is.gd)
            # AND path is short alphanumeric token (e.g. /00Qe, /abc123)
            if len(base_domain) <= 10 and path:
                path_clean = path.lstrip('/')
                if path_clean and len(path_clean) <= 12 and re.match(r'^[A-Za-z0-9_-]+$', path_clean):
                    # Short domain + short random-looking path = likely shortener
                    reasons.append(f"Heuristic: likely URL shortener ({base_domain}/{path_clean})")
                    score += 3
        except Exception:
            pass

        return score

    def _check_phishing_indicators(self, url: str, parsed, reasons: List[str]) -> int:
        score = 0
        for keyword in self.phishing_keywords:
            if keyword.search(parsed.path) or keyword.search(parsed.query):
                reasons.append(f"Phishing keyword in URL path/query: {keyword.pattern}")
                score += 1
        # Check for brand impersonation in subdomain
        domain = parsed.netloc.lower()
        brands = ['paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 'netflix', 'bank']
        for brand in brands:
            parts = domain.split('.')
            if len(parts) > 2 and brand in '.'.join(parts[:-2]) and brand not in '.'.join(parts[-2:]):
                reasons.append(f"Possible brand impersonation: '{brand}' in subdomain but not main domain")
                score += 4
        return score

    def _check_url_structure(self, url: str, parsed, reasons: List[str]) -> int:
        score = 0
        domain_parts = parsed.netloc.split('.')
        if len(domain_parts) > 4:
            reasons.append(f"Excessive subdomains ({len(domain_parts)} levels)")
            score += 2

        if '@' in parsed.netloc:
            reasons.append("URL contains @ symbol (possible credential phishing)")
            score += 3

        if re.search(r'%[0-9A-Fa-f]{2}', url):
            reasons.append("Contains URL-encoded characters")
            score += 1

        if parsed.netloc != parsed.netloc.encode('ascii', 'ignore').decode():
            reasons.append("Domain contains non-ASCII characters (possible IDN homograph attack)")
            score += 3

        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed.netloc):
            reasons.append("IP address embedded in domain")
            score += 2

        if len(parsed.path) > 200:
            reasons.append(f"Unusually long URL path ({len(parsed.path)} chars)")
            score += 1

        return score

    def _check_homograph(self, domain: str, reasons: List[str]) -> int:
        """Detect homograph/confusable characters in domain names."""
        score = 0
        # Common confusable character mappings (Latin lookalikes)
        confusables = {
            '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
            '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
            '\u0501': 'd', '\u051b': 'q', '\u0261': 'g',
            '\u0251': 'a', '\u025b': 'e', '\u0254': 'o',
            '\u1d00': 'a', '\u1d07': 'e', '\u1d0f': 'o',
            '\u0131': 'i', '\u0237': 'j',
        }
        found = []
        for ch in domain:
            if ch in confusables:
                found.append(f'{ch} → {confusables[ch]}')
        if found:
            score += 4
            reasons.append(f'Homograph attack: confusable chars in domain: {", ".join(found[:5])}')
        # Mixed-script detection (e.g. Latin + Cyrillic in same label)
        labels = domain.split('.')
        for label in labels:
            scripts = set()
            for ch in label:
                cp = ord(ch)
                if 0x0400 <= cp <= 0x04FF:
                    scripts.add('cyrillic')
                elif 0x0370 <= cp <= 0x03FF:
                    scripts.add('greek')
                elif 0x0041 <= cp <= 0x007A:
                    scripts.add('latin')
            if len(scripts) > 1:
                score += 5
                reasons.append(f'Mixed-script domain label: {label} (scripts: {", ".join(scripts)})')
                break
        return score

    def _check_query_params(self, parsed, reasons: List[str]) -> int:
        """Check query parameters for suspicious patterns."""
        score = 0
        params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

        if len(params) > 15:
            reasons.append(f"Excessive query parameters ({len(params)})")
            score += 1

        for key, values in params.items():
            val = str(values[0]) if values else ''
            if re.match(r'https?://', val) or re.match(r'https?%3A', val, re.IGNORECASE):
                reasons.append(f"Embedded URL in parameter '{key}' (possible open redirect)")
                score += 2
            if key.lower() in ('redirect', 'redir', 'url', 'next', 'return', 'returnurl', 'goto', 'dest'):
                reasons.append(f"Redirect parameter detected: '{key}'")
                score += 1

        return score

    # ------------------------------------------------------------------
    # SCORING FROM INTELLIGENCE (Phase 3)
    # ------------------------------------------------------------------

    def _score_from_intel(self, intel: Dict, reasons: List[str]) -> int:
        """Derive additional threat score from gathered intelligence."""
        score = 0

        # WHOIS scoring
        whois_data = intel.get('whois', {})
        if isinstance(whois_data, dict) and 'error' not in whois_data:
            if whois_data.get('newly_registered'):
                reasons.append(f"Domain registered less than 30 days ago")
                score += 3
            elif whois_data.get('young_domain'):
                reasons.append(f"Domain is less than 6 months old ({whois_data.get('domain_age_days')} days)")
                score += 1

        # SSL scoring
        ssl_data = intel.get('ssl', {})
        if isinstance(ssl_data, dict):
            if ssl_data.get('expired'):
                reasons.append("SSL certificate is EXPIRED")
                score += 3
            elif ssl_data.get('expiring_soon'):
                reasons.append(f"SSL certificate expiring in {ssl_data.get('days_until_expiry')} days")
                score += 1
            if 'error' in ssl_data and 'ssl' in ssl_data.get('error', '').lower():
                reasons.append("SSL connection error (possible misconfiguration)")
                score += 2

        # HTTP scoring
        http_data = intel.get('http', {})
        if isinstance(http_data, dict):
            # Redirect to internal/blocked target — instant CRITICAL escalation
            if http_data.get('blocked_redirect'):
                reasons.append(f"SAFETY: Redirect to blocked target: {http_data['blocked_redirect']}")
                score += 15
            # Post-fetch body blocked (malware/executable)
            if http_data.get('body_blocked'):
                reasons.append(f"SAFETY: Response body blocked: {http_data['body_blocked']}")
                score += 15
            # Content-Type blocked
            if http_data.get('content_type_blocked'):
                reasons.append(f"SAFETY: Dangerous Content-Type: {http_data['content_type_blocked']}")
                score += 10
            if http_data.get('ssl_error'):
                reasons.append("SSL error during HTTP request")
                score += 2
            sec_score = http_data.get('security_header_score', '')
            if sec_score:
                try:
                    present, total = sec_score.split('/')
                    if int(present) < 3:
                        reasons.append(f"Poor security headers ({sec_score})")
                        score += 2
                except Exception:
                    pass

        # GeoIP scoring
        geo_data = intel.get('geoip', {})
        if isinstance(geo_data, dict):
            if geo_data.get('is_proxy'):
                reasons.append("IP is flagged as a proxy/VPN")
                score += 2
            if geo_data.get('is_hosting'):
                reasons.append("IP belongs to a hosting/datacenter provider")
                score += 1

        # Redirect chain scoring (from dedicated redirect chain intel)
        redir_data = intel.get('redirect_chain', {})
        if isinstance(redir_data, dict):
            hops = redir_data.get('total_hops', 0)
            if hops > 3:
                reasons.append(f"Excessive redirects ({hops} hops)")
                score += 2
            chain = redir_data.get('chain', [])
            for hop in chain:
                if hop.get('note') == 'REDIRECT LOOP DETECTED':
                    reasons.append("Redirect loop detected")
                    score += 3
                    break

        # Cross-domain redirect scoring (from HTTP intel)
        if isinstance(http_data, dict):
            http_redir_chain = http_data.get('redirect_chain')
            if http_redir_chain and len(http_redir_chain) > 1:
                # Extract domains from chain
                chain_domains = []
                for hop_url in http_redir_chain:
                    try:
                        h = urllib.parse.urlparse(hop_url).hostname or ''
                        chain_domains.append(h.lower())
                    except Exception:
                        chain_domains.append('')
                # Cross-domain redirect: start domain != final domain
                if chain_domains[0] and chain_domains[-1] and chain_domains[0] != chain_domains[-1]:
                    reasons.append(f"Cross-domain redirect: {chain_domains[0]} -> {chain_domains[-1]}")
                    score += 2
                # Parked/sedo/affiliate domain detection in redirect chain
                _parked_indicators = {
                    'sedo.com', 'sedoparking.com', 'bodis.com', 'hugedomains.com',
                    'afternic.com', 'dan.com', 'godaddy.com/domainfind',
                    'parkingcrew.net', 'domainmarket.com', 'undeveloped.com',
                }
                for cd in chain_domains:
                    for parked in _parked_indicators:
                        if parked in cd:
                            reasons.append(f"Redirect to parked/domain-sales page: {cd}")
                            score += 4
                            break
            # Final URL differs from input URL (any redirect happened)
            final_url = http_data.get('final_url', '')
            if final_url:
                try:
                    final_host = urllib.parse.urlparse(final_url).hostname or ''
                    input_host = urllib.parse.urlparse(intel.get('_input_url', '')).hostname or ''
                    if final_host and input_host and final_host.lower() != input_host.lower():
                        if not any('Cross-domain redirect' in r for r in reasons):
                            reasons.append(f"Redirected to different domain: {final_host}")
                            score += 2
                except Exception:
                    pass

        # URL params scoring
        params_data = intel.get('url_params', {})
        if isinstance(params_data, dict):
            if params_data.get('has_sensitive'):
                reasons.append(f"Sensitive parameters exposed: {params_data.get('sensitive_params')}")
                score += 3

        # Multi-source threat intelligence scoring
        ti_data = intel.get('threat_intel', {})
        if isinstance(ti_data, dict) and 'error' not in ti_data:
            ti_score = ti_data.get('threat_score', 0)
            ti_reasons = ti_data.get('threat_reasons', [])
            score += ti_score
            reasons.extend(ti_reasons)

        # Content analysis scoring
        ca = intel.get('content_analysis', {})
        if isinstance(ca, dict) and 'error' not in ca:
            if ca.get('forms', {}).get('credential_harvesting'):
                reasons.append("Page contains credential harvesting form (password field + POST)")
                score += 5
            if ca.get('forms', {}).get('cross_domain_action'):
                reasons.append("Form submits data to external domain")
                score += 3
            if ca.get('iframes', {}).get('suspicious_count', 0) > 0:
                reasons.append(f"Page contains {ca['iframes']['suspicious_count']} suspicious iframe(s)")
                score += 2
            if ca.get('obfuscation', {}).get('detected'):
                pc = ca['obfuscation'].get('pattern_count', 0)
                reasons.append(f"JavaScript obfuscation detected ({pc} patterns)")
                score += 3
            if ca.get('hidden_elements', {}).get('count', 0) > 10:
                reasons.append(f"Excessive hidden elements ({ca['hidden_elements']['count']}) — possible cloaking")
                score += 2
            if ca.get('data_exfil_indicators', {}).get('detected'):
                reasons.append("Potential data exfiltration patterns found on page")
                score += 2

        # Domain analysis scoring
        da = intel.get('domain_analysis', {})
        if isinstance(da, dict) and 'error' not in da:
            ts_data = da.get('typosquatting', {})
            if ts_data.get('is_typosquat'):
                reasons.append(f"Possible typosquat of {ts_data['target_brand']} (edit distance: {ts_data['distance']})")
                score += 4
            if ts_data.get('homoglyph_detected'):
                reasons.append(f"Homoglyph attack detected targeting {ts_data['homoglyph_target']}")
                score += 5
            wp = da.get('whois_privacy', {})
            if wp.get('is_private'):
                reasons.append("WHOIS data is privacy-protected (common for both legitimate and malicious sites)")
                score += 1
            rr = da.get('registrar_risk', {})
            if rr.get('is_risky'):
                reasons.append(f"Registrar commonly used for abuse: {rr.get('registrar', '')}")
                score += 2
            dp = da.get('domain_patterns', {})
            if dp.get('excessive_hyphens'):
                reasons.append(f"Domain has {dp.get('hyphen_count', 0)} hyphens (common in phishing)")
                score += 2
            if dp.get('random_looking'):
                reasons.append("Domain appears randomly generated (possible DGA)")
                score += 3
            if dp.get('brand_in_subdomain'):
                reasons.append(f"Brand '{dp['brand_in_subdomain']}' in subdomain but not main domain")
                score += 3

        # --- Cross-signal correlation bonuses ---
        # New domain + bad TLD + no security headers = amplified risk
        is_new = whois_data.get('newly_registered') if isinstance(whois_data, dict) else False
        is_young = whois_data.get('young_domain') if isinstance(whois_data, dict) else False
        has_bad_headers = False
        if isinstance(http_data, dict):
            try:
                present, total = http_data.get('security_header_score', '0/0').split('/')
                has_bad_headers = int(present) < 3
            except Exception:
                pass
        has_cred_form = ca.get('forms', {}).get('credential_harvesting', False) if isinstance(ca, dict) else False

        if is_new and has_bad_headers:
            reasons.append("CORRELATION: Newly registered domain with poor security headers")
            score += 3
        if is_new and has_cred_form:
            reasons.append("CORRELATION: Newly registered domain with credential harvesting form")
            score += 4
        if (is_new or is_young) and da.get('typosquatting', {}).get('is_typosquat', False):
            reasons.append("CORRELATION: Young domain that is a typosquat of a known brand")
            score += 3

        # High-risk country + new domain
        if isinstance(geo_data, dict):
            cc = geo_data.get('country_code', '')
            high_risk = {'RU', 'CN', 'KP', 'IR', 'NG', 'RO', 'BY'}
            if cc in high_risk and (is_new or is_young):
                reasons.append(f"CORRELATION: Young domain hosted in high-risk country ({cc})")
                score += 2

        return score

    # ------------------------------------------------------------------
    # THREAT LEVEL DETERMINATION
    # ------------------------------------------------------------------

    def _determine_threat_level(self, score: int) -> str:
        if score >= 15:
            return URLThreatLevel.CRITICAL
        elif score >= 10:
            return URLThreatLevel.MALICIOUS
        elif score >= 5:
            return URLThreatLevel.SUSPICIOUS
        elif score >= 2:
            return URLThreatLevel.LOW
        elif score >= 1:
            return URLThreatLevel.LOW
        else:
            return URLThreatLevel.SAFE

    # ------------------------------------------------------------------
    # HELPERS
    # ------------------------------------------------------------------

    def _create_result(self, url: str, threat_level: str, message: str) -> Dict:
        return {
            'url': url,
            'domain': '',
            'threat_level': threat_level,
            'threat_score': 0,
            'reasons': [message],
            'intel': {},
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
