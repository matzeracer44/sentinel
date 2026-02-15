"""
ARGUS Content Analysis Module
Extracts intelligence from page HTML: title, meta tags, forms, iframes,
external scripts, suspicious patterns, and link analysis.
"""

import re
import logging
import urllib.parse
from typing import Dict, List, Any, Optional

from bs4 import BeautifulSoup

logger = logging.getLogger('argus.content_analysis')


class ContentAnalyzer:
    """Extracts security-relevant intelligence from HTML page content."""

    SUSPICIOUS_FORM_ACTIONS = frozenset({
        'login', 'signin', 'verify', 'confirm', 'account', 'password',
        'credential', 'auth', 'secure', 'update', 'validate', 'bank',
    })

    SUSPICIOUS_INPUT_TYPES = frozenset({
        'password', 'credit-card', 'ssn', 'cvv', 'card-number',
    })

    SUSPICIOUS_INPUT_NAMES = frozenset({
        'password', 'passwd', 'pass', 'pwd', 'credit_card', 'cc_number',
        'cvv', 'cvc', 'ssn', 'social_security', 'card_number', 'cardnumber',
        'expiry', 'exp_date', 'pin', 'secret', 'otp', 'token',
        'account_number', 'routing_number', 'bank_account',
    })

    OBFUSCATION_PATTERNS = [
        re.compile(r'eval\s*\(', re.IGNORECASE),
        re.compile(r'document\.write\s*\(', re.IGNORECASE),
        re.compile(r'unescape\s*\(', re.IGNORECASE),
        re.compile(r'fromCharCode', re.IGNORECASE),
        re.compile(r'atob\s*\(', re.IGNORECASE),
        re.compile(r'\\x[0-9a-fA-F]{2}', re.IGNORECASE),
        re.compile(r'\\u[0-9a-fA-F]{4}', re.IGNORECASE),
    ]

    def analyze(self, html: str, url: str) -> Dict[str, Any]:
        """Full content analysis of an HTML page."""
        result: Dict[str, Any] = {}
        if not html:
            return {'error': 'No HTML content to analyze'}

        try:
            soup = BeautifulSoup(html, 'html.parser')
        except Exception as e:
            return {'error': f'HTML parse failed: {str(e)}'}

        parsed_url = urllib.parse.urlparse(url)
        base_domain = parsed_url.netloc.lower().split(':')[0]

        result['page_title'] = self._extract_title(soup)
        result['meta_tags'] = self._extract_meta(soup)
        result['forms'] = self._analyze_forms(soup, base_domain)
        result['iframes'] = self._analyze_iframes(soup, base_domain)
        result['external_scripts'] = self._analyze_scripts(soup, base_domain)
        result['external_links'] = self._analyze_links(soup, base_domain)
        result['obfuscation'] = self._detect_obfuscation(html)
        result['hidden_elements'] = self._detect_hidden_elements(soup)
        result['data_exfil_indicators'] = self._detect_data_exfil(soup, html)

        # Summary risk indicators
        risk_indicators = []
        if result['forms'].get('credential_harvesting'):
            risk_indicators.append('Credential harvesting form detected')
        if result['forms'].get('cross_domain_action'):
            risk_indicators.append('Form submits to external domain')
        if result['iframes'].get('suspicious_count', 0) > 0:
            risk_indicators.append(f"{result['iframes']['suspicious_count']} suspicious iframe(s)")
        if result['obfuscation'].get('detected'):
            risk_indicators.append(f"JavaScript obfuscation detected ({result['obfuscation']['pattern_count']} patterns)")
        if result['hidden_elements'].get('count', 0) > 5:
            risk_indicators.append(f"{result['hidden_elements']['count']} hidden elements (possible cloaking)")
        if result['data_exfil_indicators'].get('detected'):
            risk_indicators.append('Potential data exfiltration patterns found')

        result['risk_indicators'] = risk_indicators
        result['risk_count'] = len(risk_indicators)

        return result

    def _extract_title(self, soup: BeautifulSoup) -> Optional[str]:
        tag = soup.find('title')
        return tag.get_text(strip=True)[:200] if tag else None

    def _extract_meta(self, soup: BeautifulSoup) -> Dict[str, str]:
        meta: Dict[str, str] = {}
        for tag in soup.find_all('meta'):
            name = tag.get('name', tag.get('property', '')).lower()
            content = tag.get('content', '')
            if name and content:
                meta[name] = content[:300]
        return meta

    def _analyze_forms(self, soup: BeautifulSoup,
                       base_domain: str) -> Dict[str, Any]:
        forms = soup.find_all('form')
        result: Dict[str, Any] = {
            'count': len(forms),
            'details': [],
            'credential_harvesting': False,
            'cross_domain_action': False,
        }
        for form in forms[:10]:
            action = form.get('action', '')
            method = form.get('method', 'GET').upper()
            inputs = []
            has_password = False
            sensitive_fields = []

            for inp in form.find_all(['input', 'select', 'textarea']):
                itype = inp.get('type', 'text').lower()
                iname = inp.get('name', '').lower()
                inputs.append({'type': itype, 'name': iname})
                if itype == 'password':
                    has_password = True
                if iname in self.SUSPICIOUS_INPUT_NAMES:
                    sensitive_fields.append(iname)

            # Cross-domain action check
            cross_domain = False
            if action:
                try:
                    action_parsed = urllib.parse.urlparse(action)
                    if action_parsed.netloc and action_parsed.netloc.lower().split(':')[0] != base_domain:
                        cross_domain = True
                        result['cross_domain_action'] = True
                except Exception:
                    pass

            # Credential harvesting heuristic
            is_harvesting = has_password and (method == 'POST')
            if is_harvesting:
                result['credential_harvesting'] = True

            form_info: Dict[str, Any] = {
                'action': action[:200] if action else '',
                'method': method,
                'input_count': len(inputs),
                'has_password_field': has_password,
                'sensitive_fields': sensitive_fields,
                'cross_domain': cross_domain,
            }
            if is_harvesting:
                form_info['warning'] = 'CREDENTIAL_HARVESTING'
            result['details'].append(form_info)

        return result

    def _analyze_iframes(self, soup: BeautifulSoup,
                         base_domain: str) -> Dict[str, Any]:
        iframes = soup.find_all('iframe')
        result: Dict[str, Any] = {
            'count': len(iframes),
            'details': [],
            'suspicious_count': 0,
        }
        for iframe in iframes[:15]:
            src = iframe.get('src', '')
            width = iframe.get('width', '')
            height = iframe.get('height', '')
            style = iframe.get('style', '')
            hidden = ('display:none' in style.replace(' ', '').lower() or
                      'visibility:hidden' in style.replace(' ', '').lower() or
                      (width in ('0', '1') and height in ('0', '1')))

            external = False
            if src:
                try:
                    p = urllib.parse.urlparse(src)
                    if p.netloc and p.netloc.lower().split(':')[0] != base_domain:
                        external = True
                except Exception:
                    pass

            suspicious = hidden or (external and not src.startswith('https://www.google.com'))
            if suspicious:
                result['suspicious_count'] += 1

            result['details'].append({
                'src': src[:200] if src else '',
                'hidden': hidden,
                'external': external,
                'suspicious': suspicious,
            })

        return result

    def _analyze_scripts(self, soup: BeautifulSoup,
                         base_domain: str) -> Dict[str, Any]:
        scripts = soup.find_all('script', src=True)
        external = []
        for s in scripts:
            src = s.get('src', '')
            if not src:
                continue
            try:
                p = urllib.parse.urlparse(src)
                if p.netloc and p.netloc.lower().split(':')[0] != base_domain:
                    external.append({
                        'src': src[:300],
                        'domain': p.netloc.lower().split(':')[0],
                        'integrity': s.get('integrity', ''),
                        'crossorigin': s.get('crossorigin', ''),
                    })
            except Exception:
                pass

        return {
            'total_scripts': len(soup.find_all('script')),
            'external_count': len(external),
            'external': external[:20],
        }

    def _analyze_links(self, soup: BeautifulSoup,
                       base_domain: str) -> Dict[str, Any]:
        links = soup.find_all('a', href=True)
        external_domains: Dict[str, int] = {}
        total = 0
        for a in links:
            href = a.get('href', '')
            try:
                p = urllib.parse.urlparse(href)
                if p.scheme in ('http', 'https') and p.netloc:
                    d = p.netloc.lower().split(':')[0]
                    if d != base_domain:
                        external_domains[d] = external_domains.get(d, 0) + 1
                        total += 1
            except Exception:
                pass

        top_external = sorted(external_domains.items(), key=lambda x: -x[1])[:15]
        return {
            'total_links': len(links),
            'external_link_count': total,
            'unique_external_domains': len(external_domains),
            'top_external_domains': [{'domain': d, 'count': c} for d, c in top_external],
        }

    def _detect_obfuscation(self, html: str) -> Dict[str, Any]:
        found = []
        for pat in self.OBFUSCATION_PATTERNS:
            matches = pat.findall(html[:50000])
            if matches:
                found.append({'pattern': pat.pattern, 'count': len(matches)})
        return {
            'detected': len(found) > 0,
            'pattern_count': sum(f['count'] for f in found),
            'patterns': found,
        }

    def _detect_hidden_elements(self, soup: BeautifulSoup) -> Dict[str, Any]:
        count = 0
        for el in soup.find_all(style=True):
            style = el.get('style', '').replace(' ', '').lower()
            if 'display:none' in style or 'visibility:hidden' in style:
                count += 1
        for el in soup.find_all(attrs={'hidden': True}):
            count += 1
        for el in soup.find_all('input', type='hidden'):
            count += 1
        return {'count': count}

    def _detect_data_exfil(self, soup: BeautifulSoup,
                           html: str) -> Dict[str, Any]:
        indicators = []
        # Beacon / pixel tracking
        for img in soup.find_all('img'):
            src = img.get('src', '')
            w = img.get('width', '')
            h = img.get('height', '')
            if (w in ('0', '1') and h in ('0', '1')) or '1x1' in src:
                indicators.append({'type': 'tracking_pixel', 'src': src[:200]})

        # navigator.sendBeacon
        if 'sendBeacon' in html[:50000]:
            indicators.append({'type': 'sendBeacon', 'note': 'navigator.sendBeacon() call detected'})

        # WebSocket connections
        ws_pattern = re.compile(r'new\s+WebSocket\s*\(', re.IGNORECASE)
        if ws_pattern.search(html[:50000]):
            indicators.append({'type': 'websocket', 'note': 'WebSocket connection detected'})

        return {
            'detected': len(indicators) > 0,
            'count': len(indicators),
            'indicators': indicators[:10],
        }
