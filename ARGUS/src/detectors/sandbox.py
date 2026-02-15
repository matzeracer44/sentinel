"""
ARGUS Sandbox Isolation System
Provides safe URL simulation when SANDBOX_MODE is enabled.
No real HTTP requests leave the machine in sandbox mode.

Components:
- IsolationProvider: Intercepts all outbound requests
- MockingEngine: Generates realistic simulation data
- verify_final_destination(): Risk-scoring for final redirect targets
"""

import random
import hashlib
import logging
import urllib.parse
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Tuple

logger = logging.getLogger('argus.sandbox')


# ---------------------------------------------------------------------------
# Killswitch — instant block when malicious destination detected
# ---------------------------------------------------------------------------

class KillswitchTriggered(Exception):
    """Raised when the sandbox killswitch fires on a malicious target."""
    def __init__(self, url: str, domain: str, reason: str, risk_score: int):
        self.url = url
        self.domain = domain
        self.reason = reason
        self.risk_score = risk_score
        super().__init__(f'KILLSWITCH: {reason} — {url}')


class Killswitch:
    """
    Evaluates a URL / domain against hard block-rules.
    If ANY rule matches, it raises KillswitchTriggered immediately
    so the scan never returns partial data to the user.

    Rules (checked in order — first match wins):
      1. Domain is in the BLACKLIST_DOMAINS set
      2. Domain contains a known-bad keyword (malware, phish, etc.)
      3. MockingEngine classifies the URL as 'malicious'
      4. verify_final_destination returns risk_score >= 75
    """

    BAD_KEYWORDS = frozenset({
        'malware', 'phish', 'exploit', 'trojan', 'ransomware',
        'botnet', 'keylogger', 'spyware', 'rootkit', 'credential-harvest',
        'fake-bank', 'scam',
    })

    def __init__(self, enabled: bool = True):
        self.enabled = enabled
        self._blocked: List[Dict[str, Any]] = []
        self._engine = MockingEngine()

    def evaluate(self, url: str) -> Optional[Dict[str, Any]]:
        """Run all block-rules. Returns a block-record dict if blocked, else None."""
        if not self.enabled:
            return None

        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]

        # Rule 1 — exact blacklist match
        if domain in BLACKLIST_DOMAINS:
            return self._block(url, domain, f'Domain {domain} is on the hardcoded blacklist', 100)

        # Rule 2 — bad keyword in domain
        for kw in self.BAD_KEYWORDS:
            if kw in domain:
                return self._block(url, domain, f'Domain contains blocked keyword: {kw}', 95)

        # Rule 3 — MockingEngine classification
        cat = self._engine._classify(url)
        if cat == 'malicious':
            return self._block(url, domain, 'MockingEngine classified URL as malicious', 90)

        # Rule 4 — high risk score from verify_final_destination
        fd = verify_final_destination(url, sandbox_mode=True)
        if fd.get('risk_score', 0) >= 75:
            return self._block(url, domain,
                               f"Final destination risk score {fd['risk_score']} >= 75",
                               fd['risk_score'])

        return None

    def _block(self, url: str, domain: str, reason: str,
               risk_score: int) -> Dict[str, Any]:
        record = {
            'url': url,
            'domain': domain,
            'reason': reason,
            'risk_score': risk_score,
            'action': 'BLOCKED',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }
        self._blocked.append(record)
        logger.critical('KILLSWITCH TRIGGERED: %s — %s (score %d)',
                        reason, url, risk_score)
        return record

    @property
    def blocked_count(self) -> int:
        return len(self._blocked)

    def get_blocked_log(self) -> List[Dict[str, Any]]:
        return list(self._blocked)

# ---------------------------------------------------------------------------
# Known-bad domains used by the MockingEngine for malicious simulations
# ---------------------------------------------------------------------------
BLACKLIST_DOMAINS = frozenset({
    'malware-distribution.ru', 'phish-kit-store.cn', 'credential-harvest.tk',
    'ransomware-c2.ir', 'botnet-panel.ng', 'exploit-kit.cc', 'dark-redirect.ml',
    'scam-lottery.ga', 'fake-bank-login.cf', 'trojan-dropper.gq',
    'keylogger-host.top', 'cryptominer-pool.xyz', 'adware-push.buzz',
    'spyware-cdn.club', 'rootkit-update.work',
})

MARKETING_DOMAINS = frozenset({
    'track.email-campaign.com', 'click.newsletter-service.net',
    'redirect.ad-network.io', 'go.affiliate-link.co',
    'trk.marketing-platform.com', 'out.promo-mailer.net',
})

HIGH_RISK_COUNTRIES = {'RU', 'CN', 'KP', 'IR', 'NG', 'RO', 'BY'}


# ---------------------------------------------------------------------------
# IsolationProvider
# ---------------------------------------------------------------------------

class IsolationProvider:
    """
    When active, intercepts every outbound call from URLDetector and
    returns MockingEngine data instead of real network traffic.
    """

    def __init__(self, enabled: bool = False):
        self.enabled = enabled
        self._engine = MockingEngine()
        self._call_log: List[Dict[str, Any]] = []
        self.killswitch = Killswitch(enabled=enabled)
        logger.info('SandboxIsolationProvider initialised (enabled=%s)', enabled)

    @property
    def is_active(self) -> bool:
        return self.enabled

    def toggle(self, state: bool) -> None:
        self.enabled = state
        self.killswitch.enabled = state
        logger.info('Sandbox toggled to %s', state)

    def get_call_log(self) -> List[Dict[str, Any]]:
        return list(self._call_log)

    # -- interceptors -------------------------------------------------------

    def intercept_dns(self, domain: str) -> Dict[str, Any]:
        self._log('dns', domain)
        return self._engine.mock_dns(domain)

    def intercept_whois(self, domain: str) -> Dict[str, Any]:
        self._log('whois', domain)
        return self._engine.mock_whois(domain)

    def intercept_http(self, url: str) -> Dict[str, Any]:
        self._log('http', url)
        return self._engine.mock_http(url)

    def intercept_ssl(self, domain: str, port: Optional[int]) -> Dict[str, Any]:
        self._log('ssl', domain)
        return self._engine.mock_ssl(domain)

    def intercept_geoip(self, ip: str) -> Dict[str, Any]:
        self._log('geoip', ip)
        return self._engine.mock_geoip(ip)

    def intercept_ip_whois(self, ip: str) -> Dict[str, Any]:
        self._log('ip_whois', ip)
        return self._engine.mock_ip_whois(ip)

    def intercept_reverse_dns(self, ip: str) -> Dict[str, Any]:
        self._log('reverse_dns', ip)
        return self._engine.mock_reverse_dns(ip)

    def intercept_redirect_chain(self, url: str) -> Dict[str, Any]:
        self._log('redirect_chain', url)
        chain_data = self._engine.mock_redirect_chain(url)

        # ── Killswitch check on every hop + final URL ──
        final_url = chain_data.get('final_url', url)
        block = self.killswitch.evaluate(final_url)
        if block:
            chain_data['killswitch'] = block
        else:
            for hop in chain_data.get('chain', []):
                hop_block = self.killswitch.evaluate(hop.get('url', ''))
                if hop_block:
                    chain_data['killswitch'] = hop_block
                    break

        return chain_data

    def intercept_content_analysis(self, url: str, domain: str) -> Dict[str, Any]:
        self._log('content_analysis', url)
        return self._engine.mock_content_analysis(url, domain)

    def intercept_threat_intel(self, url: str, domain: str,
                               ip: Optional[str]) -> Dict[str, Any]:
        self._log('threat_intel', url)
        return self._engine.mock_threat_intel(url, domain, ip)

    # -- internal -----------------------------------------------------------

    def _log(self, kind: str, target: str) -> None:
        self._call_log.append({
            'type': kind,
            'target': target,
            'timestamp': datetime.now(timezone.utc).isoformat(),
        })


# ---------------------------------------------------------------------------
# MockingEngine
# ---------------------------------------------------------------------------

class MockingEngine:
    """Generates deterministic-yet-realistic simulation data."""

    def _seed(self, value: str) -> random.Random:
        return random.Random(hashlib.sha256(value.encode()).hexdigest())

    def _fake_ip(self, seed_str: str) -> str:
        rng = self._seed(seed_str)
        return (f'{rng.randint(1, 223)}.{rng.randint(0, 255)}'
                f'.{rng.randint(0, 255)}.{rng.randint(1, 254)}')

    # -- classify URL -------------------------------------------------------

    def _classify(self, url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        tld = domain.split('.')[-1] if '.' in domain else ''
        suspicious_tlds = {'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top',
                           'buzz', 'club'}

        bad_kw = ('malware', 'phish', 'exploit', 'trojan', 'ransomware',
                  'botnet', 'keylogger', 'spyware', 'rootkit')
        if domain in BLACKLIST_DOMAINS or any(b in domain for b in bad_kw):
            return 'malicious'
        if domain in MARKETING_DOMAINS or any(
                m in domain for m in ('track.', 'click.', 'redirect.',
                                      'go.', 'trk.', 'out.')):
            return 'marketing'
        if tld in suspicious_tlds:
            return 'suspicious'
        if any(kw in url.lower() for kw in (
                'login', 'verify', 'secure', 'update', 'account',
                'password', 'credential')):
            return 'suspicious'
        return 'clean'

    # -- DNS ----------------------------------------------------------------

    def mock_dns(self, domain: str) -> Dict[str, Any]:
        ip = self._fake_ip(domain)
        rng = self._seed(domain)
        return {
            'A': [ip],
            'AAAA': [],
            'NS': ['ns1.sandbox-dns.local', 'ns2.sandbox-dns.local'],
            'MX': [{'priority': 10, 'exchange': f'mail.{domain}'}],
            'TXT': [f'v=spf1 include:_spf.{domain} ~all'],
            'SOA': {
                'mname': 'ns1.sandbox-dns.local',
                'rname': f'admin.{domain}',
                'serial': rng.randint(2024010100, 2025123100),
                'refresh': 3600, 'retry': 900,
                'expire': 604800, 'minimum': 86400,
            },
            'spf': [f'v=spf1 include:_spf.{domain} ~all'],
            'dmarc': [f'v=DMARC1; p=reject; rua=mailto:dmarc@{domain}'],
            'has_dnssec': rng.choice([True, False]),
        }

    # -- WHOIS --------------------------------------------------------------

    def mock_whois(self, domain: str) -> Dict[str, Any]:
        rng = self._seed(domain)
        cat = self._classify(f'https://{domain}')
        if cat == 'malicious':
            age_days = rng.randint(1, 14)
        elif cat == 'suspicious':
            age_days = rng.randint(15, 90)
        elif cat == 'marketing':
            age_days = rng.randint(200, 800)
        else:
            age_days = rng.randint(365, 5000)

        created = datetime.now(timezone.utc) - timedelta(days=age_days)
        expires = created + timedelta(days=365)
        registrars = ['NameCheap Inc.', 'GoDaddy LLC', 'Tucows Domains',
                      'Gandi SAS', 'Dynadot LLC']
        countries = ['US', 'DE', 'NL', 'RU', 'CN', 'GB', 'FR', 'JP']

        base_domain = domain.split('.')[0].upper()
        result: Dict[str, Any] = {
            'registrar': rng.choice(registrars),
            'registrant_org': f'SANDBOX-ORG-{base_domain}',
            'registrant_country': (rng.choice(['RU', 'CN', 'KP'])
                                   if cat == 'malicious'
                                   else rng.choice(countries)),
            'registrant_state': None,
            'registrant_city': None,
            'registrant_name': ('REDACTED FOR PRIVACY' if cat == 'clean'
                                else f'sandbox-registrant-{rng.randint(1000, 9999)}'),
            'registrant_email': ('REDACTED FOR PRIVACY' if cat == 'clean'
                                 else f'abuse@{domain}'),
            'creation_date': created.isoformat(),
            'expiration_date': expires.isoformat(),
            'updated_date': (created + timedelta(
                days=rng.randint(1, max(age_days, 2)))).isoformat(),
            'name_servers': ['ns1.sandbox-dns.local',
                             'ns2.sandbox-dns.local'],
            'status': (['clientTransferProhibited'] if cat == 'clean'
                       else ['serverHold']),
            'dnssec': ('signedDelegation' if rng.random() > 0.5
                       else 'unsigned'),
            'domain_age_days': age_days,
        }
        if age_days < 30:
            result['newly_registered'] = True
        elif age_days < 180:
            result['young_domain'] = True
        return result

    # -- HTTP ---------------------------------------------------------------

    def mock_http(self, url: str) -> Dict[str, Any]:
        rng = self._seed(url)
        cat = self._classify(url)
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]

        status = 200
        if cat == 'malicious':
            status = rng.choice([200, 403, 500])

        sec_headers: Dict[str, str] = {}
        header_names = [
            'Strict-Transport-Security', 'Content-Security-Policy',
            'X-Content-Type-Options', 'X-Frame-Options',
            'X-XSS-Protection', 'Referrer-Policy',
            'Permissions-Policy', 'Cross-Origin-Opener-Policy',
            'Cross-Origin-Resource-Policy', 'Cross-Origin-Embedder-Policy',
        ]
        for h in header_names:
            if cat == 'clean' and rng.random() > 0.2:
                sec_headers[h] = 'present'
            elif cat == 'suspicious' and rng.random() > 0.6:
                sec_headers[h] = 'present'
            else:
                sec_headers[h] = 'MISSING'

        present_count = sum(1 for v in sec_headers.values() if v != 'MISSING')
        servers = ['nginx/1.24.0', 'Apache/2.4.57', 'cloudflare',
                   'Microsoft-IIS/10.0']
        techs: List[str] = []
        if cat == 'clean':
            techs = rng.sample(['Cloudflare', 'React', 'Google Analytics',
                                'jQuery', 'Nginx'],
                               k=rng.randint(1, 3))
        elif cat == 'marketing':
            techs = ['Google Tag Manager', 'Facebook Pixel',
                     'Google Analytics']

        return {
            'status_code': status,
            'final_url': url,
            'response_time_ms': (rng.randint(80, 2500) if cat != 'malicious'
                                 else rng.randint(3000, 8000)),
            'server': rng.choice(servers),
            'powered_by': rng.choice([None, 'PHP/8.2', 'Express',
                                      'ASP.NET']),
            'content_type': 'text/html; charset=utf-8',
            'security_headers': sec_headers,
            'security_header_score': f'{present_count}/{len(header_names)}',
            'cookies': ([{
                'name': 'session_id', 'domain': domain, 'path': '/',
                'secure': cat == 'clean', 'httponly': cat == 'clean',
                'expires': None,
            }] if rng.random() > 0.3 else []),
            'technologies': techs,
            'all_headers': {'Server': rng.choice(servers),
                            'Content-Type': 'text/html'},
        }

    # -- SSL ----------------------------------------------------------------

    def mock_ssl(self, domain: str) -> Dict[str, Any]:
        rng = self._seed(domain)
        cat = self._classify(f'https://{domain}')
        now = datetime.now(timezone.utc)

        if cat == 'malicious':
            not_before = now - timedelta(days=rng.randint(1, 10))
            not_after = now + timedelta(days=rng.randint(-5, 30))
        elif cat == 'suspicious':
            not_before = now - timedelta(days=rng.randint(30, 90))
            not_after = now + timedelta(days=rng.randint(10, 90))
        else:
            not_before = now - timedelta(days=rng.randint(30, 300))
            not_after = now + timedelta(days=rng.randint(90, 365))

        days_left = (not_after - now).days
        issuer_cn = ("Let's Encrypt Authority X3" if cat != 'malicious'
                     else 'Self-Signed CA')
        issuer_org = ("Let's Encrypt" if cat != 'malicious' else 'Unknown')
        base_domain = domain.split('.')[0].upper()

        result: Dict[str, Any] = {
            'subject': {'commonName': domain,
                        'organizationName': f'SANDBOX-{base_domain}'},
            'issuer': {'commonName': issuer_cn,
                       'organizationName': issuer_org},
            'not_before': not_before.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'not_after': not_after.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'serial_number': hashlib.md5(
                domain.encode()).hexdigest().upper()[:20],
            'version': 'v3',
            'signature_algorithm': 'sha256WithRSAEncryption',
            'tls_version': ('TLSv1.3' if cat == 'clean'
                            else rng.choice(['TLSv1.2', 'TLSv1.1'])),
            'days_until_expiry': days_left,
            'subject_alt_names': [{'type': 'DNS', 'value': domain},
                                  {'type': 'DNS', 'value': f'www.{domain}'}],
            'key_usage': ['Digital Signature', 'Key Encipherment'],
            'ocsp': ['http://ocsp.sandbox.local'],
            'ca_issuers': [],
            'crl': [],
        }
        if days_left < 0:
            result['expired'] = True
        elif days_left < 30:
            result['expiring_soon'] = True
        return result

    # -- GeoIP --------------------------------------------------------------

    def mock_geoip(self, ip: str) -> Dict[str, Any]:
        rng = self._seed(ip)
        countries = [
            ('United States', 'US', 'North America', 37.7749, -122.4194,
             'America/Los_Angeles', 'Cloudflare Inc.'),
            ('Germany', 'DE', 'Europe', 50.1109, 8.6821,
             'Europe/Berlin', 'Hetzner Online GmbH'),
            ('Netherlands', 'NL', 'Europe', 52.3676, 4.9041,
             'Europe/Amsterdam', 'DigitalOcean LLC'),
            ('Russia', 'RU', 'Europe', 55.7558, 37.6173,
             'Europe/Moscow', 'Rostelecom'),
            ('China', 'CN', 'Asia', 39.9042, 116.4074,
             'Asia/Shanghai', 'China Telecom'),
            ('Japan', 'JP', 'Asia', 35.6762, 139.6503,
             'Asia/Tokyo', 'NTT Communications'),
        ]
        c = rng.choice(countries)
        return {
            'ip': ip,
            'continent': c[2],
            'country': c[0],
            'country_code': c[1],
            'region': 'Sandbox Region',
            'city': 'Sandbox City',
            'zip': f'{rng.randint(10000, 99999)}',
            'latitude': round(c[3] + rng.uniform(-1, 1), 4),
            'longitude': round(c[4] + rng.uniform(-1, 1), 4),
            'timezone': c[5],
            'isp': c[6],
            'org': c[6],
            'as_number': f'AS{rng.randint(1000, 65000)}',
            'as_name': c[6],
            'reverse_dns': f'{ip.replace(".", "-")}.sandbox.local',
            'is_mobile': False,
            'is_proxy': rng.random() < 0.1,
            'is_hosting': rng.random() < 0.4,
        }

    # -- IP WHOIS -----------------------------------------------------------

    def mock_ip_whois(self, ip: str) -> Dict[str, Any]:
        rng = self._seed(ip)
        prefix = ip.rsplit('.', 1)[0]
        return {
            'asn': f'{rng.randint(1000, 65000)}',
            'asn_cidr': f'{prefix}.0/24',
            'asn_country': rng.choice(['US', 'DE', 'NL', 'RU', 'CN', 'JP']),
            'asn_description': f'SANDBOX-ASN-{rng.randint(100, 999)}',
            'asn_registry': rng.choice(['arin', 'ripe', 'apnic']),
            'network_name': f'SANDBOX-NET-{rng.randint(100, 999)}',
            'network_cidr': f'{prefix}.0/24',
            'network_country': rng.choice(['US', 'DE', 'NL']),
            'network_start': f'{prefix}.0',
            'network_end': f'{prefix}.255',
        }

    # -- Reverse DNS --------------------------------------------------------

    def mock_reverse_dns(self, ip: str) -> Dict[str, Any]:
        return {
            'ip': ip,
            'hostname': f'{ip.replace(".", "-")}.sandbox.local',
        }

    # -- Content Analysis ---------------------------------------------------

    def mock_content_analysis(self, url: str, domain: str) -> Dict[str, Any]:
        rng = self._seed(url)
        cat = self._classify(url)

        forms_count = rng.randint(0, 3) if cat != 'malicious' else rng.randint(1, 5)
        has_password = cat in ('malicious', 'suspicious') and rng.random() > 0.3
        cross_domain = cat == 'malicious' and rng.random() > 0.4

        forms_details = []
        for i in range(forms_count):
            forms_details.append({
                'method': rng.choice(['POST', 'GET']),
                'action': f'https://{domain}/submit' if not cross_domain else f'https://evil-collect-{rng.randint(100,999)}.tk/grab',
                'input_count': rng.randint(2, 8),
                'has_password_field': has_password and i == 0,
                'cross_domain': cross_domain and i == 0,
                'sensitive_fields': ['password', 'email'] if has_password and i == 0 else [],
                'warning': 'Credential harvesting suspected' if has_password and cross_domain and i == 0 else None,
            })

        ext_scripts = rng.randint(0, 8)
        total_scripts = ext_scripts + rng.randint(1, 5)
        ext_links = rng.randint(2, 20)
        ext_domains = min(ext_links, rng.randint(1, 8))

        top_domains = [{'domain': f'cdn{i}.example.com', 'count': rng.randint(1, 5)} for i in range(min(ext_domains, 5))]

        result: Dict[str, Any] = {
            'page_title': f'Sandbox Page - {domain}',
            'meta_tags': {
                'description': f'Simulated page content for {domain}',
                'viewport': 'width=device-width, initial-scale=1.0',
                'robots': 'index, follow',
            },
            'forms': {
                'count': forms_count,
                'credential_harvesting': has_password and cross_domain,
                'cross_domain_action': cross_domain,
                'details': forms_details,
            },
            'iframes': {
                'count': rng.randint(0, 3) if cat != 'malicious' else rng.randint(2, 6),
                'suspicious_count': 0 if cat == 'clean' else rng.randint(0, 2),
            },
            'external_scripts': {
                'total_scripts': total_scripts,
                'external_count': ext_scripts,
            },
            'external_links': {
                'external_link_count': ext_links,
                'unique_external_domains': ext_domains,
                'top_external_domains': top_domains,
            },
            'obfuscation': {
                'detected': cat == 'malicious' and rng.random() > 0.5,
                'pattern_count': rng.randint(3, 12) if cat == 'malicious' else 0,
            },
            'hidden_elements': {
                'count': rng.randint(0, 3) if cat != 'malicious' else rng.randint(5, 20),
            },
            'data_exfil_indicators': {
                'detected': cat == 'malicious' and rng.random() > 0.6,
                'count': rng.randint(1, 4) if cat == 'malicious' else 0,
            },
            'risk_indicators': [],
        }

        if cat == 'malicious':
            result['risk_indicators'] = [
                'Multiple cross-domain form actions detected',
                'JavaScript obfuscation patterns found',
                'Hidden form elements collecting sensitive data',
            ][:rng.randint(1, 3)]
        elif cat == 'suspicious':
            result['risk_indicators'] = [
                'Form submits to external domain',
            ] if cross_domain else []

        return result

    # -- Redirect Chain -----------------------------------------------------

    def mock_redirect_chain(self, url: str) -> Dict[str, Any]:
        cat = self._classify(url)
        rng = self._seed(url)

        if cat == 'clean':
            chain = [{'hop': 1, 'url': url, 'status_code': 200,
                      'server': 'nginx/1.24.0'}]
        elif cat == 'marketing':
            chain = self._build_marketing_chain(url, rng)
        elif cat == 'suspicious':
            chain = self._build_suspicious_chain(url, rng)
        else:
            chain = self._build_malicious_chain(url, rng)

        return {
            'total_hops': len(chain),
            'chain': chain,
            'final_url': chain[-1]['url'] if chain else url,
            'has_redirects': len(chain) > 1,
        }

    def _build_marketing_chain(self, url: str,
                                rng: random.Random) -> List[Dict]:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower().split(':')[0]
        hops_count = rng.randint(3, 6)
        marketing_hops = [
            f'https://track.email-campaign.com/r/{rng.randint(10000, 99999)}',
            f'https://click.newsletter-service.net/c/{rng.randint(10000, 99999)}',
            f'https://redirect.ad-network.io/go/{rng.randint(10000, 99999)}',
            f'https://go.affiliate-link.co/out/{rng.randint(10000, 99999)}',
        ]
        chain: List[Dict] = []
        current = url
        for i in range(min(hops_count, len(marketing_hops) + 1)):
            if i < len(marketing_hops):
                nxt = (marketing_hops[i]
                       if i < len(marketing_hops) - 1
                       else f'https://{domain}/landing')
                chain.append({'hop': i + 1, 'url': current,
                              'status_code': 302, 'server': 'cloudflare',
                              'redirects_to': nxt})
                current = nxt
            else:
                chain.append({'hop': i + 1, 'url': current,
                              'status_code': 200, 'server': 'nginx/1.24.0'})
        return chain

    def _build_suspicious_chain(self, url: str,
                                 rng: random.Random) -> List[Dict]:
        hops_count = rng.randint(2, 4)
        chain: List[Dict] = []
        current = url
        for i in range(hops_count):
            if i < hops_count - 1:
                tld = rng.choice(['tk', 'ml', 'ga'])
                nxt = (f'https://redir-{rng.randint(100, 999)}'
                       f'.suspicious-{tld}/p/{rng.randint(1000, 9999)}')
                chain.append({'hop': i + 1, 'url': current,
                              'status_code': 301, 'server': 'Apache/2.4.57',
                              'redirects_to': nxt})
                current = nxt
            else:
                chain.append({'hop': i + 1, 'url': current,
                              'status_code': 200, 'server': 'Apache/2.4.57'})
        return chain

    def _build_malicious_chain(self, url: str,
                                rng: random.Random) -> List[Dict]:
        hops_count = rng.randint(4, 8)
        chain: List[Dict] = []
        current = url
        for i in range(hops_count):
            if i < hops_count - 1:
                tld = rng.choice(['ru', 'cn', 'tk'])
                slug = hashlib.md5(
                    str(rng.random()).encode()).hexdigest()[:8]
                nxt = (f'https://hop{i + 1}-{rng.randint(100, 999)}'
                       f'.malware-cdn-{rng.randint(1, 50)}.{tld}/{slug}')
                chain.append({'hop': i + 1, 'url': current,
                              'status_code': 302, 'server': 'Unknown',
                              'redirects_to': nxt})
                current = nxt
            else:
                bl_domain = rng.choice(list(BLACKLIST_DOMAINS))
                final = f'https://{bl_domain}/payload'
                chain.append({'hop': i + 1, 'url': final,
                              'status_code': 200, 'server': 'Unknown'})
                current = final
        return chain

    # -- Threat Intel -------------------------------------------------------

    def mock_threat_intel(self, url: str, domain: str,
                          ip: Optional[str]) -> Dict[str, Any]:
        cat = self._classify(url)
        rng = self._seed(url)
        results: Dict[str, Any] = {}

        results['virustotal'] = self._mock_vt(cat, domain, rng)

        if ip:
            results['abuseipdb'] = self._mock_abuseipdb(cat, ip, rng)

        results['alienvault_otx'] = self._mock_otx(cat, rng)

        if ip:
            results['ipinfo'] = self._mock_ipinfo(cat, ip, rng)

        score, reasons = self._score_mock_results(results)
        verdict = 'clean'
        if score >= 10:
            verdict = 'malicious'
        elif score >= 5:
            verdict = 'suspicious'
        elif score >= 2:
            verdict = 'low_risk'

        return {
            'results': results,
            'threat_score': score,
            'threat_reasons': reasons,
            'verdict': verdict,
            'sources_queried': list(results.keys()),
            'sources_available': [k for k, v in results.items()
                                  if v.get('available')],
        }

    def _mock_vt(self, cat: str, domain: str,
                  rng: random.Random) -> Dict[str, Any]:
        if cat == 'malicious':
            mal = rng.randint(8, 30)
            sus = rng.randint(2, 8)
            harmless = rng.randint(30, 50)
            return {
                'source': 'virustotal', 'available': True,
                'scan_submitted': False,
                'detection_ratio': f'{mal}/{mal + sus + harmless}',
                'stats': {'malicious': mal, 'suspicious': sus,
                          'harmless': harmless,
                          'undetected': rng.randint(5, 15)},
                'reputation': rng.randint(-80, -20),
                'times_submitted': rng.randint(50, 500),
                'title': f'Malicious page - {domain}',
                'categories': {'Forcepoint': 'malicious',
                               'Sophos': 'malware'},
                'tags': ['malware', 'phishing'],
                'detections': [
                    {'engine': 'Kaspersky', 'category': 'malicious',
                     'result': 'Phishing'},
                    {'engine': 'Bitdefender', 'category': 'malicious',
                     'result': 'Malware'},
                    {'engine': 'ESET', 'category': 'malicious',
                     'result': 'Trojan.Generic'},
                ],
            }
        elif cat == 'suspicious':
            sus = rng.randint(1, 4)
            harmless = rng.randint(50, 70)
            return {
                'source': 'virustotal', 'available': True,
                'scan_submitted': False,
                'detection_ratio': f'{sus}/{sus + harmless}',
                'stats': {'malicious': 0, 'suspicious': sus,
                          'harmless': harmless,
                          'undetected': rng.randint(2, 8)},
                'reputation': rng.randint(-10, 5),
                'times_submitted': rng.randint(5, 50),
                'title': domain, 'categories': {}, 'tags': [],
                'detections': [],
            }
        else:
            harmless = rng.randint(70, 90)
            return {
                'source': 'virustotal', 'available': True,
                'scan_submitted': False,
                'detection_ratio': f'0/{harmless}',
                'stats': {'malicious': 0, 'suspicious': 0,
                          'harmless': harmless,
                          'undetected': rng.randint(0, 5)},
                'reputation': rng.randint(10, 100),
                'times_submitted': rng.randint(100, 10000),
                'title': domain, 'categories': {}, 'tags': [],
                'detections': [],
            }

    def _mock_abuseipdb(self, cat: str, ip: str,
                         rng: random.Random) -> Dict[str, Any]:
        conf = 0
        if cat == 'malicious':
            conf = rng.randint(70, 100)
        elif cat == 'suspicious':
            conf = rng.randint(10, 50)
        reports = (rng.randint(0, 500) if cat == 'malicious'
                   else rng.randint(0, 20))
        last_rep = None
        if conf > 0:
            last_rep = (datetime.now(timezone.utc)
                        - timedelta(hours=rng.randint(1, 720))).isoformat()
        return {
            'source': 'abuseipdb', 'available': True,
            'ip': ip, 'abuse_confidence_score': conf,
            'total_reports': reports,
            'isp': 'Sandbox ISP',
            'usage_type': 'Data Center/Web Hosting/Transit',
            'country_code': rng.choice(['US', 'DE', 'RU', 'CN']),
            'is_tor': rng.random() < 0.05,
            'last_reported_at': last_rep,
        }

    def _mock_otx(self, cat: str,
                   rng: random.Random) -> Dict[str, Any]:
        pulse_count = 0
        if cat == 'malicious':
            pulse_count = rng.randint(3, 20)
        elif cat == 'suspicious':
            pulse_count = rng.randint(0, 3)
        pulses = []
        if pulse_count > 0:
            pulses = [{
                'name': f'Threat Pulse #{rng.randint(1000, 9999)}',
                'tags': ['malware', 'c2'],
                'adversary': 'APT-SANDBOX',
            }]
        return {
            'source': 'alienvault_otx', 'available': True,
            'pulse_count': pulse_count,
            'pulses': pulses,
        }

    def _mock_ipinfo(self, cat: str, ip: str,
                      rng: random.Random) -> Dict[str, Any]:
        if cat == 'malicious':
            cc = rng.choice(['RU', 'CN', 'KP', 'IR'])
        else:
            cc = rng.choice(['US', 'DE', 'RU', 'CN', 'NL', 'JP'])
        country_map = {
            'US': 'United States', 'DE': 'Germany', 'RU': 'Russia',
            'CN': 'China', 'NL': 'Netherlands', 'JP': 'Japan',
            'KP': 'North Korea', 'IR': 'Iran',
        }
        continent_map = {
            'US': ('NA', 'North America'), 'DE': ('EU', 'Europe'),
            'RU': ('EU', 'Europe'), 'CN': ('AS', 'Asia'),
            'NL': ('EU', 'Europe'), 'JP': ('AS', 'Asia'),
            'KP': ('AS', 'Asia'), 'IR': ('AS', 'Asia'),
        }
        cc_info = continent_map.get(cc, ('XX', 'Unknown'))
        return {
            'source': 'ipinfo', 'available': True,
            'ip': ip, 'asn': f'AS{rng.randint(1000, 65000)}',
            'as_name': 'Sandbox Hosting', 'as_domain': 'sandbox.local',
            'country_code': cc, 'country': country_map.get(cc, cc),
            'continent_code': cc_info[0], 'continent': cc_info[1],
        }

    @staticmethod
    def _score_mock_results(results: Dict[str, Any]) -> Tuple[int, List[str]]:
        score = 0
        reasons: List[str] = []

        vt = results.get('virustotal', {})
        if vt.get('available') and not vt.get('scan_submitted'):
            stats = vt.get('stats', {})
            mal = stats.get('malicious', 0)
            sus = stats.get('suspicious', 0)
            if mal > 0:
                score += min(mal * 2, 15)
                reasons.append(
                    f"VirusTotal: {vt.get('detection_ratio')} engines "
                    f"flagged as malicious")
            if sus > 0:
                score += min(sus, 5)
                reasons.append(
                    f"VirusTotal: {sus} engines flagged as suspicious")

        adb = results.get('abuseipdb', {})
        if adb.get('available'):
            conf = adb.get('abuse_confidence_score', 0)
            if conf >= 80:
                score += 6
                reasons.append(f'AbuseIPDB: abuse confidence {conf}%')
            elif conf >= 40:
                score += 3
                reasons.append(
                    f'AbuseIPDB: moderate abuse confidence {conf}%')

        otx = results.get('alienvault_otx', {})
        if otx.get('available'):
            pc = otx.get('pulse_count', 0)
            if pc > 0:
                score += min(pc, 6)
                reasons.append(f'AlienVault OTX: {pc} threat pulses')

        ipi = results.get('ipinfo', {})
        if ipi.get('available'):
            cc = ipi.get('country_code', '')
            if cc in HIGH_RISK_COUNTRIES:
                score += 1
                reasons.append(
                    f"IPinfo: IP in high-risk country "
                    f"({ipi.get('country', cc)})")

        return score, reasons


# ---------------------------------------------------------------------------
# verify_final_destination
# ---------------------------------------------------------------------------

def verify_final_destination(url: str,
                             sandbox_mode: bool = False) -> Dict[str, Any]:
    """
    Analyse the final destination of a redirect chain.

    In sandbox mode  -> deterministic risk score from MockingEngine.
    In live mode     -> placeholder for a real reputation API.
    """
    parsed = urllib.parse.urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]

    if sandbox_mode:
        engine = MockingEngine()
        cat = engine._classify(url)
        rng = engine._seed(url)

        if cat == 'malicious':
            risk = rng.randint(75, 100)
            verdict = 'DANGEROUS'
            color = 'red'
        elif cat in ('suspicious', 'marketing'):
            risk = rng.randint(30, 74)
            verdict = 'WARNING'
            color = 'yellow'
        else:
            risk = rng.randint(0, 29)
            verdict = 'SAFE'
            color = 'green'

        bad_kw = ('malware', 'phish', 'exploit', 'trojan')
        in_blacklist = (domain in BLACKLIST_DOMAINS
                        or any(b in domain for b in bad_kw))

        return {
            'url': url,
            'domain': domain,
            'risk_score': risk,
            'verdict': verdict,
            'color': color,
            'in_blacklist': in_blacklist,
            'sandbox': True,
        }

    # --- Live mode (stub for real reputation API) ---
    return {
        'url': url,
        'domain': domain,
        'risk_score': None,
        'verdict': 'UNKNOWN',
        'color': 'gray',
        'in_blacklist': False,
        'sandbox': False,
        'note': ('Live reputation API not configured. '
                 'Enable sandbox mode or add a reputation API key.'),
    }
