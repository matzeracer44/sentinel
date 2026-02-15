"""
ARGUS Safety Guard — Config-Driven Environment Protection
Enforces the url_fetch section of config.yaml before every outbound request.

Pipeline (VALIDATE → FETCH → VERIFY, per WHITECODE v2):
  Step 1 — Parse URL strictly (reject malformed)
  Step 2 — Verify scheme ∈ allowed_schemes (http, https)
  Step 3 — Resolve DNS BEFORE connecting (anti-DNS-rebinding)
  Step 4 — Block if resolved IP is private/internal/metadata
  Step 5 — FETCH the URL (timeout, max response size)
  Step 6 — Follow redirects max N hops, re-validate each hop BEFORE connecting
  Step 7 — Post-fetch: validate Content-Type, scan body for executables/scripts/malware

Anti-Projection (host isolation):
  - NEVER write outside data/ and logs/
  - NEVER exec/eval fetched payloads
  - NEVER deserialize untrusted data (no pickle, no unsafe yaml)
  - ALL file paths canonicalized against allowlist
"""

import os
import re
import time
import socket
import logging
import ipaddress
import threading
import urllib.parse
from pathlib import Path
from typing import Optional, Tuple, Set, Dict, List

logger = logging.getLogger('argus.safety_guard')


# ---------------------------------------------------------------------------
# Known-bad domains (shared with sandbox killswitch)
# ---------------------------------------------------------------------------
BLACKLIST_DOMAINS: Set[str] = frozenset({
    'malware-distribution.ru', 'phish-kit-store.cn', 'credential-harvest.tk',
    'ransomware-c2.ir', 'botnet-panel.ng', 'exploit-kit.cc', 'dark-redirect.ml',
    'scam-lottery.ga', 'fake-bank-login.cf', 'trojan-dropper.gq',
    'keylogger-host.top', 'cryptominer-pool.xyz', 'adware-push.buzz',
    'spyware-cdn.club', 'rootkit-update.work',
})

BAD_KEYWORDS = frozenset({
    'malware', 'phish', 'exploit', 'trojan', 'ransomware',
    'botnet', 'keylogger', 'spyware', 'rootkit', 'credential-harvest',
    'fake-bank', 'scam',
})

BLOCKED_SCHEMES = frozenset({
    'file', 'ftp', 'gopher', 'data', 'javascript', 'vbscript',
    'ldap', 'ldaps', 'dict', 'sftp', 'tftp', 'telnet', 'ssh',
})

# RFC 1918 + loopback + link-local + cloud metadata + other reserved ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network('10.0.0.0/8'),
    ipaddress.ip_network('172.16.0.0/12'),
    ipaddress.ip_network('192.168.0.0/16'),
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),     # link-local (includes cloud metadata)
    ipaddress.ip_network('0.0.0.0/8'),
    ipaddress.ip_network('100.64.0.0/10'),       # Carrier-grade NAT
    ipaddress.ip_network('198.18.0.0/15'),        # Benchmarking
    ipaddress.ip_network('::1/128'),              # IPv6 loopback
    ipaddress.ip_network('fc00::/7'),             # IPv6 ULA
    ipaddress.ip_network('fe80::/10'),            # IPv6 link-local
]

# Cloud metadata endpoints (AWS, GCP, Azure, etc.)
CLOUD_METADATA_IPS = frozenset({
    '169.254.169.254',   # AWS / GCP / Azure / DigitalOcean
    'fd00:ec2::254',     # AWS IPv6 metadata
})

# Anti-projection: only these directories may be written to
ALLOWED_WRITE_DIRS = {'data', 'logs'}


class SafetyViolation(Exception):
    """Raised when a safety check fails. The scan should be blocked."""
    def __init__(self, reason: str, url: str = ''):
        self.reason = reason
        self.url = url
        super().__init__(f'SAFETY BLOCK: {reason} [{url}]')


class SafetyGuard:
    """
    Config-driven safety layer. Reads url_fetch from config.yaml.
    Implements the VALIDATE → FETCH → VERIFY pipeline per WHITECODE v2.
    """

    def __init__(self, server_port: int = 8080, config: dict = None):
        cfg = config or {}
        self._server_port = server_port
        self._domain_timestamps: Dict[str, float] = {}
        self._min_interval = 0.5

        # --- Pre-fetch checks (from url_fetch.pre_fetch_checks) ---
        pre = cfg.get('pre_fetch_checks', {})
        self._block_private = pre.get('block_private_ips', True)
        self._block_localhost = pre.get('block_localhost', True)
        self._block_metadata = pre.get('block_metadata', True)
        self._allowed_schemes = set(s.lower() for s in pre.get('allowed_schemes', ['http', 'https']))
        self._dns_rebinding = pre.get('dns_rebinding_protection', True)
        self._resolve_before = pre.get('resolve_dns_first', True)

        # --- Post-fetch checks (from url_fetch.post_fetch_checks) ---
        post = cfg.get('post_fetch_checks', {})
        self._content_type_validation = post.get('validate_content_type', True)
        self._max_response_bytes = post.get('max_response_size_mb', 10) * 1024 * 1024
        self._scan_response_body = post.get('scan_response_body', True)
        self._block_executable = post.get('block_executable_content', True)
        self._block_script_injection = post.get('block_script_injection', True)

        # --- Redirect policy (from url_fetch.redirect_policy) ---
        redir = cfg.get('redirect_policy', {})
        self._follow_redirects = redir.get('follow_redirects', True)
        self._max_hops = redir.get('max_hops', 5)
        self._revalidate_each_hop = redir.get('revalidate_each_hop', True)

        # --- On-fail behaviour ---
        self._on_fail = cfg.get('on_fail', 'block_and_log')

        logger.info('SafetyGuard initialised: block_private=%s block_localhost=%s '
                     'block_metadata=%s dns_rebinding=%s schemes=%s '
                     'max_response=%dMB scan_body=%s block_exec=%s block_script=%s '
                     'max_hops=%d on_fail=%s',
                     self._block_private, self._block_localhost,
                     self._block_metadata, self._dns_rebinding,
                     self._allowed_schemes,
                     self._max_response_bytes // (1024 * 1024),
                     self._scan_response_body, self._block_executable,
                     self._block_script_injection, self._max_hops,
                     self._on_fail)

    # ------------------------------------------------------------------
    # Public API — call before ANY network request
    # ------------------------------------------------------------------

    def validate_scan_target(self, url: str) -> Tuple[bool, Optional[str]]:
        """Full pre-scan validation (7-step protocol). Returns (safe, reason)."""
        try:
            # Step 1: strict parse
            parsed = urllib.parse.urlparse(url)
            if not parsed.netloc:
                raise SafetyViolation('Malformed URL: no host', url)

            # Step 2: scheme check
            self._check_scheme(url, parsed)

            # Step 3+4: blacklist + domain/IP safety (includes DNS pre-resolve)
            self._check_blacklist(url, parsed)
            self._check_domain_safety(url, parsed)

            logger.debug('SAFETY PASS: %s', url)
            return True, None
        except SafetyViolation as e:
            logger.warning('SAFETY BLOCK url=%s reason=%s', url, e.reason)
            return False, e.reason

    def validate_redirect_target(self, url: str) -> Tuple[bool, Optional[str]]:
        """Step 5: validate each redirect hop."""
        try:
            parsed = urllib.parse.urlparse(url)
            self._check_scheme(url, parsed)
            self._check_domain_safety(url, parsed)
            logger.debug('REDIRECT PASS: %s', url)
            return True, None
        except SafetyViolation as e:
            logger.warning('REDIRECT BLOCKED url=%s reason=%s', url, e.reason)
            return False, e.reason

    def validate_ip(self, ip_str: str) -> Tuple[bool, Optional[str]]:
        """Check if an IP is safe to connect to."""
        try:
            ip = ipaddress.ip_address(ip_str)
            if self._block_metadata and ip_str in CLOUD_METADATA_IPS:
                return False, f'Cloud metadata endpoint blocked: {ip_str}'
            if self._is_private_ip(ip):
                return False, f'Private/internal IP blocked: {ip_str}'
            return True, None
        except ValueError:
            return True, None

    def validate_content_type(self, content_type: str, expected: str = 'text/html') -> Tuple[bool, Optional[str]]:
        """Step 6: validate Content-Type header matches expected type."""
        if not self._content_type_validation:
            return True, None
        if not content_type:
            return True, None  # missing header — allow but log
        ct = content_type.lower().split(';')[0].strip()
        # Allow common web content types for scanning
        safe_types = {
            'text/html', 'text/plain', 'application/json',
            'application/xml', 'text/xml', 'text/css',
            'application/javascript', 'text/javascript',
            'application/xhtml+xml',
        }
        if ct in safe_types:
            return True, None
        # Block binary/executable types
        dangerous_types = {
            'application/octet-stream', 'application/x-executable',
            'application/x-msdos-program', 'application/x-msdownload',
            'application/vnd.microsoft.portable-executable',
        }
        if ct in dangerous_types:
            return False, f'Dangerous Content-Type blocked: {ct}'
        return True, None  # unknown types — allow for scanning

    def safe_read_body(self, response, max_bytes: int = None) -> str:
        """Safely read response body with config-driven size cap."""
        cap = max_bytes or self._max_response_bytes
        chunks = []
        total = 0
        try:
            for chunk in response.iter_content(chunk_size=8192, decode_unicode=True):
                if chunk:
                    if isinstance(chunk, bytes):
                        chunk = chunk.decode('utf-8', errors='replace')
                    total += len(chunk)
                    if total > cap:
                        chunks.append(chunk[:cap - (total - len(chunk))])
                        logger.warning('Response body truncated at %d bytes (cap: %d)', total, cap)
                        break
                    chunks.append(chunk)
        except Exception as e:
            logger.debug('Body read error: %s', e)
        return ''.join(chunks)

    def scan_body_safety(self, body: str, url: str = '') -> Tuple[bool, Optional[str]]:
        """Step 7: Post-fetch response body validation.
        Checks for executable content, script injection, and malware patterns."""
        if not body:
            return True, None

        # Block executable content patterns (.exe, .bat, .ps1, .sh, PE headers, ELF)
        if self._block_executable:
            exe_patterns = [
                (b'MZ', 'PE/MZ executable header'),
                (b'\x7fELF', 'ELF executable header'),
                (b'#!/', 'Shell script shebang'),
            ]
            body_start = body[:512].encode('utf-8', errors='replace')
            for sig, desc in exe_patterns:
                if body_start.startswith(sig):
                    reason = f'Executable content blocked: {desc}'
                    logger.warning('POST-FETCH BLOCK url=%s reason=%s', url, reason)
                    return False, reason

            # Check for download-triggering patterns
            exe_extensions = re.compile(
                r'\.(exe|bat|cmd|ps1|sh|msi|dll|scr|com|vbs|wsf|jar)\b', re.IGNORECASE)
            content_disp = re.search(r'filename\s*=\s*["\']?([^"\';\s]+)', body[:2000])
            if content_disp and exe_extensions.search(content_disp.group(1)):
                reason = f'Executable filename in body: {content_disp.group(1)}'
                logger.warning('POST-FETCH BLOCK url=%s reason=%s', url, reason)
                return False, reason

        # Block script injection patterns (eval-able code in response)
        if self._block_script_injection:
            injection_patterns = [
                (r'<script[^>]*>.*?(eval|document\.write|window\.location\s*=|\.innerHTML\s*=)',
                 'Inline script with dangerous call'),
                (r'javascript\s*:', 'javascript: URI in body'),
                (r'on(error|load|click|mouseover)\s*=\s*["\']',
                 'Inline event handler injection'),
                (r'document\.cookie', 'Cookie access in response body'),
                (r'new\s+Function\s*\(', 'Dynamic Function constructor'),
                (r'eval\s*\(\s*(atob|unescape|decodeURI)',
                 'Obfuscated eval pattern'),
            ]
            body_sample = body[:100_000]  # scan first 100KB
            for pattern, desc in injection_patterns:
                if re.search(pattern, body_sample, re.IGNORECASE | re.DOTALL):
                    reason = f'Script injection pattern: {desc}'
                    logger.warning('POST-FETCH FLAG url=%s reason=%s', url, reason)
                    # Flag but don't block — many legitimate sites use these patterns
                    # The detection engine will score this separately
                    break

        # Malware signature scan (common patterns)
        if self._scan_response_body:
            malware_sigs = [
                (r'powershell\s+-[eE]nc', 'PowerShell encoded command'),
                (r'cmd\.exe\s*/[cC]', 'cmd.exe execution'),
                (r'WScript\.Shell', 'WScript shell object'),
                (r'(?<!\btype\s*of\s)(?<!["\'])new\s+ActiveXObject\s*\(', 'ActiveX instantiation'),
                (r'HKEY_(LOCAL_MACHINE|CURRENT_USER)', 'Registry key reference'),
                (r'\\\\[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\\',
                 'UNC path to IP address'),
            ]
            body_sample = body[:200_000]
            for pattern, desc in malware_sigs:
                if re.search(pattern, body_sample, re.IGNORECASE):
                    reason = f'Malware signature: {desc}'
                    logger.warning('POST-FETCH MALWARE url=%s reason=%s', url, reason)
                    return False, reason

        return True, None

    @property
    def max_redirect_hops(self) -> int:
        """Max redirect hops from config."""
        return self._max_hops

    def rate_check(self, domain: str) -> bool:
        """Simple per-domain rate limiter."""
        now = time.time()
        last = self._domain_timestamps.get(domain, 0)
        if now - last < self._min_interval:
            time.sleep(self._min_interval - (now - last))
        self._domain_timestamps[domain] = time.time()
        return True

    # ------------------------------------------------------------------
    # Anti-Projection: Host Isolation
    # ------------------------------------------------------------------

    @staticmethod
    def validate_file_path(path_str: str) -> Tuple[bool, Optional[str]]:
        """Ensure file writes only go to allowed directories (data/, logs/).
        Canonicalizes path to prevent traversal attacks."""
        try:
            p = Path(path_str).resolve()
            project_root = Path(__file__).resolve().parent.parent.parent
            try:
                rel = p.relative_to(project_root)
            except ValueError:
                return False, f'Path outside project root: {path_str}'
            top_dir = rel.parts[0] if rel.parts else ''
            if top_dir not in ALLOWED_WRITE_DIRS:
                return False, f'Write blocked: {top_dir}/ is not in allowed dirs {ALLOWED_WRITE_DIRS}'
            return True, None
        except Exception as e:
            return False, f'Path validation error: {e}'

    @staticmethod
    def is_safe_deserialize(data: bytes, format_hint: str = '') -> bool:
        """Block pickle and unsafe YAML deserialization."""
        if format_hint.lower() in ('pickle', 'pkl'):
            logger.warning('BLOCKED: pickle deserialization attempt')
            return False
        # Check for pickle magic bytes
        if data[:2] in (b'\x80\x05', b'\x80\x04', b'\x80\x03', b'\x80\x02'):
            logger.warning('BLOCKED: pickle magic bytes detected')
            return False
        return True

    # ------------------------------------------------------------------
    # Internal checks
    # ------------------------------------------------------------------

    def _check_scheme(self, url: str, parsed=None):
        if parsed is None:
            parsed = urllib.parse.urlparse(url)
        scheme = (parsed.scheme or '').lower()
        if scheme in BLOCKED_SCHEMES:
            raise SafetyViolation(f'Dangerous URI scheme blocked: {scheme}://', url)
        if scheme and scheme not in self._allowed_schemes:
            raise SafetyViolation(f'Scheme not in allowed list ({self._allowed_schemes}): {scheme}://', url)

    def _check_blacklist(self, url: str, parsed=None):
        if parsed is None:
            parsed = urllib.parse.urlparse(url)
        host = self._extract_host(parsed)
        if host in BLACKLIST_DOMAINS:
            raise SafetyViolation(f'Blacklisted domain: {host}', url)
        for kw in BAD_KEYWORDS:
            if kw in host:
                raise SafetyViolation(f'Bad keyword in domain: {kw}', url)

    def _check_domain_safety(self, url: str, parsed=None):
        if parsed is None:
            parsed = urllib.parse.urlparse(url)
        host = self._extract_host(parsed)
        port_str = self._extract_port(parsed)

        # Normalize encoded IPs (decimal, hex, octal, shorthand) to standard form
        normalized_ip = self._normalize_ip_host(host)
        check_host = normalized_ip or host  # use normalized if available

        # Block localhost (covers all encodings)
        _localhost_names = {'localhost', '127.0.0.1', '::1', '0.0.0.0', '0'}
        if self._block_localhost and (check_host in _localhost_names or host in _localhost_names):
            raise SafetyViolation('Blocked: target is localhost (self-attack prevention)', url)

        # Check if host is a raw IP (use normalized form if available)
        ip_to_check = normalized_ip or host
        try:
            ip = ipaddress.ip_address(ip_to_check)
            # Cloud metadata check
            if self._block_metadata and str(ip) in CLOUD_METADATA_IPS:
                raise SafetyViolation(f'Blocked: cloud metadata endpoint {ip} (SSRF prevention)', url)
            if self._block_private and self._is_private_ip(ip):
                raise SafetyViolation(f'Blocked: private/internal IP {ip} (SSRF prevention)', url)
        except ValueError:
            pass  # not an IP literal

        # Step 3: DNS pre-resolve (anti-DNS-rebinding)
        if self._dns_rebinding and self._resolve_before:
            violation_box = [None]
            def _resolve():
                try:
                    infos = socket.getaddrinfo(host, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
                    for family, _, _, _, sockaddr in infos:
                        ip_str = sockaddr[0]
                        try:
                            ip = ipaddress.ip_address(ip_str)
                            if self._block_metadata and ip_str in CLOUD_METADATA_IPS:
                                violation_box[0] = SafetyViolation(
                                    f'Blocked: {host} resolves to cloud metadata IP {ip_str}', url)
                                return
                            if self._block_private and self._is_private_ip(ip):
                                violation_box[0] = SafetyViolation(
                                    f'Blocked: {host} resolves to private IP {ip_str} (DNS rebinding)', url)
                                return
                        except ValueError:
                            continue
                except Exception:
                    pass
            t = threading.Thread(target=_resolve, daemon=True)
            t.start()
            t.join(timeout=3)
            if violation_box[0]:
                raise violation_box[0]

        # Block requests to ARGUS's own port
        _self_hosts = {'localhost', '127.0.0.1', '::1', '0.0.0.0', '0'}
        if (check_host in _self_hosts or host in _self_hosts) and port_str == str(self._server_port):
            raise SafetyViolation(f'Blocked: target is ARGUS server port {self._server_port}', url)

    @staticmethod
    def _normalize_ip_host(host: str) -> Optional[str]:
        """Normalize encoded IP representations to standard dotted-decimal.
        Handles: decimal (2130706433), hex (0x7f000001), octal (0177.0.0.1),
        shorthand (0 = 0.0.0.0), mixed formats.
        Returns normalized IP string or None if host is not an encoded IP."""
        if not host:
            return None

        # Already a valid standard IP?
        try:
            ip = ipaddress.ip_address(host)
            return str(ip)
        except ValueError:
            pass

        # Single integer (decimal): e.g. 2130706433 -> 127.0.0.1
        try:
            num = int(host, 0)  # auto-detect base (0x hex, 0o octal, decimal)
            if 0 <= num <= 0xFFFFFFFF:
                return str(ipaddress.ip_address(num))
        except (ValueError, OverflowError):
            pass

        # Dotted with octal/hex octets: e.g. 0177.0.0.1, 0x7f.0.0.1
        parts = host.split('.')
        if 2 <= len(parts) <= 4:
            try:
                octets = []
                for part in parts:
                    part = part.strip()
                    if part.startswith('0x') or part.startswith('0X'):
                        val = int(part, 16)
                    elif part.startswith('0') and len(part) > 1 and part.isdigit():
                        val = int(part, 8)  # octal
                    else:
                        val = int(part)
                    if not (0 <= val <= 255):
                        raise ValueError(f'Octet out of range: {val}')
                    octets.append(val)
                # Pad to 4 octets if fewer (e.g. 127.1 -> 127.0.0.1)
                while len(octets) < 4:
                    octets.insert(-1, 0) if len(octets) > 1 else octets.append(0)
                normalized = '.'.join(str(o) for o in octets[:4])
                ip = ipaddress.ip_address(normalized)
                return str(ip)
            except (ValueError, OverflowError):
                pass

        return None

    @staticmethod
    def _extract_host(parsed) -> str:
        """Extract hostname from parsed URL, handling IPv6 brackets."""
        netloc = (parsed.netloc or '').lower()
        if netloc.startswith('['):
            bracket_end = netloc.find(']')
            if bracket_end != -1:
                return netloc[1:bracket_end]
        hostname = parsed.hostname or ''
        return hostname.lower()

    @staticmethod
    def _extract_port(parsed) -> str:
        """Extract port string from parsed URL."""
        try:
            if parsed.port:
                return str(parsed.port)
        except (ValueError, TypeError):
            pass
        return ''

    def _is_private_ip(self, ip: ipaddress._BaseAddress) -> bool:
        for net in PRIVATE_NETWORKS:
            if ip in net:
                return True
        return False


# ---------------------------------------------------------------------------
# Singleton for the application (config-aware)
# ---------------------------------------------------------------------------
_guard: Optional[SafetyGuard] = None


def get_safety_guard(server_port: int = 8080, config: dict = None) -> SafetyGuard:
    """Get or create the singleton SafetyGuard. Pass config on first call."""
    global _guard
    if _guard is None:
        _guard = SafetyGuard(server_port=server_port, config=config or {})
    return _guard
