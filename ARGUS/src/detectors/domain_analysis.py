"""
ARGUS Domain Analysis Module
Typosquatting detection, WHOIS privacy detection, registrar reputation.
"""

import re
import logging
from typing import Dict, List, Any, Optional

logger = logging.getLogger('argus.domain_analysis')

# Well-known brands for typosquatting detection
BRAND_DOMAINS = {
    'google.com', 'facebook.com', 'amazon.com', 'apple.com', 'microsoft.com',
    'netflix.com', 'paypal.com', 'instagram.com', 'twitter.com', 'linkedin.com',
    'github.com', 'youtube.com', 'whatsapp.com', 'telegram.org', 'dropbox.com',
    'spotify.com', 'zoom.us', 'slack.com', 'adobe.com', 'ebay.com',
    'chase.com', 'wellsfargo.com', 'bankofamerica.com', 'citibank.com',
    'usps.com', 'fedex.com', 'dhl.com', 'ups.com',
}

WHOIS_PRIVACY_INDICATORS = frozenset({
    'redacted for privacy', 'whoisguard', 'domains by proxy',
    'contact privacy', 'privacy protect', 'withheld for privacy',
    'data protected', 'identity protection', 'whois privacy',
    'domain privacy', 'private registration', 'perfect privacy',
    'anonymize', 'privacydotlink', 'whoisprivacycorp',
})

RISKY_REGISTRARS = frozenset({
    'namecheap', 'namesilo', 'porkbun', 'epik', 'njalla',
    'regtons', 'internet.bs', 'hosting concepts',
})

REPUTABLE_REGISTRARS = frozenset({
    'markmonitor', 'csc corporate domains', 'safenames',
    'networksolutions', 'register.com', 'cloudflare',
})


def levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            cost = 0 if c1 == c2 else 1
            curr.append(min(curr[j] + 1, prev[j + 1] + 1, prev[j] + cost))
        prev = curr
    return prev[-1]


HOMOGLYPHS = {
    'a': ['а', '@', '4'],  # Cyrillic а
    'e': ['е', '3'],       # Cyrillic е
    'o': ['о', '0'],       # Cyrillic о
    'i': ['і', '1', 'l'],  # Cyrillic і
    'c': ['с'],             # Cyrillic с
    's': ['ѕ', '5', '$'],   # Cyrillic ѕ
    'p': ['р'],             # Cyrillic р
    'x': ['х'],             # Cyrillic х
    'y': ['у'],             # Cyrillic у
    'n': ['п'],
    'l': ['1', 'I', 'i'],
    'g': ['9', 'q'],
    'b': ['d', '6'],
    'd': ['b'],
    'w': ['vv'],
    'm': ['rn', 'nn'],
}


class DomainAnalyzer:
    """Analyzes domain names for typosquatting, privacy, and registrar risk."""

    def analyze(self, domain: str, whois_data: Optional[Dict] = None) -> Dict[str, Any]:
        result: Dict[str, Any] = {}
        result['typosquatting'] = self.check_typosquatting(domain)
        result['whois_privacy'] = self.check_whois_privacy(whois_data) if whois_data else {}
        result['registrar_risk'] = self.check_registrar(whois_data) if whois_data else {}
        result['domain_patterns'] = self.check_domain_patterns(domain)

        risk_indicators = []
        ts = result['typosquatting']
        if ts.get('is_typosquat'):
            risk_indicators.append(f"Possible typosquat of {ts['target_brand']} (distance: {ts['distance']})")
        if ts.get('homoglyph_detected'):
            risk_indicators.append(f"Homoglyph attack detected targeting {ts['homoglyph_target']}")
        wp = result['whois_privacy']
        if wp.get('is_private'):
            risk_indicators.append('WHOIS registration data is privacy-protected')
        rr = result['registrar_risk']
        if rr.get('is_risky'):
            risk_indicators.append(f"Registrar '{rr.get('registrar', '')}' is commonly used for abuse")
        dp = result['domain_patterns']
        if dp.get('excessive_hyphens'):
            risk_indicators.append('Domain contains excessive hyphens (common in phishing)')
        if dp.get('brand_in_subdomain'):
            risk_indicators.append(f"Brand name '{dp['brand_in_subdomain']}' found in subdomain")
        if dp.get('random_looking'):
            risk_indicators.append('Domain appears randomly generated (possible DGA)')

        result['risk_indicators'] = risk_indicators
        result['risk_count'] = len(risk_indicators)
        return result

    def check_typosquatting(self, domain: str) -> Dict[str, Any]:
        """Check if domain is a typosquat of a known brand."""
        base = domain.lower().split(':')[0]
        parts = base.split('.')
        if len(parts) < 2:
            return {'is_typosquat': False}

        # Use the second-level domain for comparison
        sld = parts[-2] if len(parts) >= 2 else parts[0]
        tld = parts[-1]

        best_match = None
        best_distance = 999

        for brand in BRAND_DOMAINS:
            brand_parts = brand.split('.')
            brand_sld = brand_parts[0]

            if sld == brand_sld:
                continue  # exact match, not a typosquat

            dist = levenshtein(sld, brand_sld)
            # Only flag if very close (1-2 edits) and domain is short enough
            if dist <= 2 and dist < best_distance and len(sld) >= 3:
                best_distance = dist
                best_match = brand

        # Homoglyph check
        homoglyph_target = self._check_homoglyphs(sld)

        result: Dict[str, Any] = {
            'is_typosquat': best_match is not None and best_distance <= 2,
            'target_brand': best_match,
            'distance': best_distance if best_match else None,
            'homoglyph_detected': homoglyph_target is not None,
            'homoglyph_target': homoglyph_target,
        }
        return result

    def _check_homoglyphs(self, sld: str) -> Optional[str]:
        """Check if domain uses homoglyph characters to impersonate a brand."""
        for brand in BRAND_DOMAINS:
            brand_sld = brand.split('.')[0]
            if len(sld) != len(brand_sld):
                continue
            mismatches = 0
            is_homoglyph = True
            for c_sld, c_brand in zip(sld, brand_sld):
                if c_sld == c_brand:
                    continue
                # Check if c_sld is a homoglyph of c_brand
                glyphs = HOMOGLYPHS.get(c_brand, [])
                if c_sld in glyphs:
                    mismatches += 1
                else:
                    is_homoglyph = False
                    break
            if is_homoglyph and mismatches > 0:
                return brand
        return None

    def check_whois_privacy(self, whois_data: Dict) -> Dict[str, Any]:
        """Detect WHOIS privacy protection."""
        if not whois_data or whois_data.get('error'):
            return {'is_private': False, 'reason': 'No WHOIS data'}

        fields_to_check = [
            whois_data.get('registrant_name', ''),
            whois_data.get('registrant_org', ''),
            whois_data.get('registrant_email', ''),
        ]
        text = ' '.join(str(f) for f in fields_to_check if f).lower()

        for indicator in WHOIS_PRIVACY_INDICATORS:
            if indicator in text:
                return {
                    'is_private': True,
                    'reason': f'Privacy indicator found: {indicator}',
                    'service': indicator,
                }

        return {'is_private': False}

    def check_registrar(self, whois_data: Dict) -> Dict[str, Any]:
        """Evaluate registrar reputation."""
        if not whois_data or whois_data.get('error'):
            return {}

        registrar = str(whois_data.get('registrar', '')).lower()
        if not registrar:
            return {'registrar': '', 'is_risky': False, 'is_reputable': False}

        is_risky = any(r in registrar for r in RISKY_REGISTRARS)
        is_reputable = any(r in registrar for r in REPUTABLE_REGISTRARS)

        return {
            'registrar': whois_data.get('registrar', ''),
            'is_risky': is_risky,
            'is_reputable': is_reputable,
        }

    def check_domain_patterns(self, domain: str) -> Dict[str, Any]:
        """Check for suspicious domain patterns."""
        base = domain.lower().split(':')[0]
        parts = base.split('.')
        sld = parts[-2] if len(parts) >= 2 else parts[0]

        result: Dict[str, Any] = {}

        # Excessive hyphens
        hyphen_count = sld.count('-')
        result['excessive_hyphens'] = hyphen_count >= 3
        result['hyphen_count'] = hyphen_count

        # Brand in subdomain but not in main domain
        if len(parts) > 2:
            subdomain = '.'.join(parts[:-2])
            for brand in BRAND_DOMAINS:
                brand_name = brand.split('.')[0]
                if brand_name in subdomain and brand_name not in sld:
                    result['brand_in_subdomain'] = brand_name
                    break

        # Random-looking domain (high consonant ratio, no dictionary words)
        vowels = set('aeiou')
        consonant_count = sum(1 for c in sld if c.isalpha() and c not in vowels)
        alpha_count = sum(1 for c in sld if c.isalpha())
        if alpha_count > 4:
            consonant_ratio = consonant_count / alpha_count
            digit_ratio = sum(1 for c in sld if c.isdigit()) / len(sld) if sld else 0
            result['random_looking'] = (consonant_ratio > 0.8 or digit_ratio > 0.4) and len(sld) > 6
        else:
            result['random_looking'] = False

        # Domain length
        result['domain_length'] = len(sld)
        result['is_long'] = len(sld) > 20

        return result
