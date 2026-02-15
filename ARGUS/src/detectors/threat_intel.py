"""
ARGUS Multi-Signal Threat Intelligence Aggregator
Integrates: VirusTotal v3, AbuseIPDB, AlienVault OTX — all queried in parallel.
"""

import os
import base64
import logging
import urllib.parse
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
import time as _time

logger = logging.getLogger('argus.threat_intel')

_MAX_RETRIES = 1
_BACKOFF_BASE = 1.0  # seconds

_SENSITIVE_PARAMS = frozenset({'token', 'key', 'apikey', 'api_key', 'x-apikey', 'secret'})

def _sanitize_url(url: str) -> str:
    """Strip sensitive query params from a URL for safe logging."""
    try:
        p = urllib.parse.urlparse(url)
        qs = urllib.parse.parse_qs(p.query, keep_blank_values=True)
        for k in list(qs.keys()):
            if k.lower() in _SENSITIVE_PARAMS:
                qs[k] = ['***']
        clean_query = urllib.parse.urlencode(qs, doseq=True)
        return urllib.parse.urlunparse(p._replace(query=clean_query))
    except Exception:
        return '<redacted-url>'


def _safe_json(resp, max_size: int = 5 * 1024 * 1024) -> Optional[dict]:
    """Safely parse JSON from an API response. Treats response as untrusted.
    Rejects: non-JSON content types, oversized bodies, non-dict top-level."""
    if resp is None:
        return None
    ct = resp.headers.get('Content-Type', '')
    if 'json' not in ct and 'javascript' not in ct:
        logger.debug('API response has non-JSON Content-Type: %s', ct)
        return None
    content_length = resp.headers.get('Content-Length')
    if content_length and int(content_length) > max_size:
        logger.warning('API response too large (%s bytes), rejecting', content_length)
        return None
    try:
        data = resp.json()
    except (ValueError, TypeError) as e:
        logger.debug('API response JSON parse failed: %s', e)
        return None
    if not isinstance(data, dict):
        logger.debug('API response top-level is not dict: %s', type(data).__name__)
        return None
    return data


def _sg(session, url, **kw):
    kw.setdefault('timeout', 6)
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = session.get(url, **kw)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', _BACKOFF_BASE * (attempt + 1)))
                logger.warning("Rate-limited by %s — waiting %ds (attempt %d)", _sanitize_url(url), retry_after, attempt + 1)
                _time.sleep(min(retry_after, 30))
                continue
            return resp
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            if attempt < _MAX_RETRIES:
                wait = _BACKOFF_BASE * (2 ** attempt)
                logger.debug("GET %s retry %d after %.1fs: %s", _sanitize_url(url), attempt + 1, wait, e)
                _time.sleep(wait)
            else:
                logger.debug("GET %s failed after %d attempts: %s", _sanitize_url(url), _MAX_RETRIES + 1, e)
                return None
        except Exception as e:
            logger.debug("GET %s: %s", _sanitize_url(url), e)
            return None
    return None


def _sp(session, url, **kw):
    kw.setdefault('timeout', 6)
    for attempt in range(_MAX_RETRIES + 1):
        try:
            resp = session.post(url, **kw)
            if resp.status_code == 429:
                retry_after = int(resp.headers.get('Retry-After', _BACKOFF_BASE * (attempt + 1)))
                logger.warning("Rate-limited by %s — waiting %ds", _sanitize_url(url), retry_after)
                _time.sleep(min(retry_after, 30))
                continue
            return resp
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            if attempt < _MAX_RETRIES:
                _time.sleep(_BACKOFF_BASE * (2 ** attempt))
            else:
                logger.debug("POST %s failed after %d attempts: %s", _sanitize_url(url), _MAX_RETRIES + 1, e)
                return None
        except Exception as e:
            logger.debug("POST %s: %s", _sanitize_url(url), e)
            return None
    return None


# ===================================================================
# VirusTotal API v3
# ===================================================================

class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, session: requests.Session):
        self.key = api_key
        self.s = session
        self.h = {"x-apikey": api_key, "Accept": "application/json"}

    def _uid(self, url: str) -> str:
        return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    def analyze_url(self, url: str) -> Dict[str, Any]:
        r: Dict[str, Any] = {"source": "virustotal", "available": False}
        if not self.key:
            r["error"] = "No API key configured"
            return r
        resp = _sg(self.s, f"{self.BASE}/urls/{self._uid(url)}", headers=self.h)
        if resp and resp.status_code == 200:
            body = _safe_json(resp)
            if not body:
                r["error"] = "VT response failed validation"
                return r
            d = body.get("data", {})
            a = d.get("attributes", {})
            st = a.get("last_analysis_stats", {})
            r.update({
                "available": True,
                "scan_id": d.get("id"),
                "scan_date": a.get("last_analysis_date"),
                "times_submitted": a.get("times_submitted"),
                "reputation": a.get("reputation"),
                "categories": a.get("categories", {}),
                "total_votes": a.get("total_votes", {}),
                "last_http_response_code": a.get("last_http_response_code"),
                "last_final_url": a.get("last_final_url"),
                "title": a.get("title"),
                "trackers": a.get("trackers", {}),
                "stats": {
                    "malicious": st.get("malicious", 0),
                    "suspicious": st.get("suspicious", 0),
                    "harmless": st.get("harmless", 0),
                    "undetected": st.get("undetected", 0),
                    "timeout": st.get("timeout", 0),
                },
                "detection_ratio": f"{st.get('malicious', 0)}/{sum(st.values()) if st else 0}",
                "tags": a.get("tags", []),
            })
            engines = a.get("last_analysis_results", {})
            dets = []
            for en, ed in engines.items():
                if ed.get("category") in ("malicious", "suspicious"):
                    dets.append({"engine": en, "category": ed.get("category"), "result": ed.get("result")})
            r["detections"] = dets[:20]
        elif resp and resp.status_code == 404:
            sr = _sp(self.s, f"{self.BASE}/urls", headers=self.h, data={"url": url})
            if sr and sr.status_code == 200:
                sr_body = _safe_json(sr) or {}
                r.update({"available": True, "scan_submitted": True, "scan_id": sr_body.get("data", {}).get("id"),
                           "info": "URL submitted for scanning"})
            else:
                r["error"] = "Failed to submit URL for scanning"
        else:
            r["error"] = f"VT API error (HTTP {resp.status_code if resp else 'N/A'})"
        return r

    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        r: Dict[str, Any] = {"source": "virustotal_domain", "available": False}
        if not self.key:
            return r
        resp = _sg(self.s, f"{self.BASE}/domains/{domain}", headers=self.h)
        if resp and resp.status_code == 200:
            body = _safe_json(resp)
            if not body:
                return r
            d = body.get("data", {})
            a = d.get("attributes", {})
            st = a.get("last_analysis_stats", {})
            r.update({
                "available": True, "reputation": a.get("reputation"),
                "categories": a.get("categories", {}),
                "popularity_ranks": a.get("popularity_ranks", {}),
                "creation_date": a.get("creation_date"),
                "registrar": a.get("registrar"),
                "stats": {"malicious": st.get("malicious", 0), "suspicious": st.get("suspicious", 0),
                           "harmless": st.get("harmless", 0), "undetected": st.get("undetected", 0)},
                "tags": a.get("tags", []),
            })
        return r


# ===================================================================
# AbuseIPDB
# ===================================================================

class AbuseIPDBClient:
    BASE = "https://api.abuseipdb.com/api/v2"

    def __init__(self, api_key: str, session: requests.Session):
        self.key = api_key
        self.s = session

    def check_ip(self, ip: str) -> Dict[str, Any]:
        r: Dict[str, Any] = {"source": "abuseipdb", "available": False}
        if not self.key:
            r["error"] = "No API key configured"
            return r
        resp = _sg(self.s, f"{self.BASE}/check",
                   headers={"Key": self.key, "Accept": "application/json"},
                   params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""})
        if resp and resp.status_code == 200:
            body = _safe_json(resp)
            if not body:
                r["error"] = "AbuseIPDB response failed validation"
                return r
            d = body.get("data", {})
            r.update({
                "available": True, "ip": d.get("ipAddress"),
                "is_public": d.get("isPublic"),
                "abuse_confidence_score": d.get("abuseConfidenceScore"),
                "country_code": d.get("countryCode"),
                "isp": d.get("isp"), "domain": d.get("domain"),
                "usage_type": d.get("usageType"),
                "total_reports": d.get("totalReports"),
                "num_distinct_users": d.get("numDistinctUsers"),
                "last_reported_at": d.get("lastReportedAt"),
                "is_tor": d.get("isTor", False),
                "is_whitelisted": d.get("isWhitelisted"),
            })
            reports = d.get("reports", [])
            if reports:
                r["recent_reports"] = [
                    {"reported_at": rp.get("reportedAt"), "categories": rp.get("categories", []),
                     "comment": (rp.get("comment") or "")[:200], "reporter_country": rp.get("reporterCountryCode")}
                    for rp in reports[:10]
                ]
        else:
            r["error"] = f"AbuseIPDB error (HTTP {resp.status_code if resp else 'N/A'})"
        return r


# ===================================================================
# AlienVault OTX
# ===================================================================

class AlienVaultOTXClient:
    BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str, session: requests.Session):
        self.key = api_key
        self.s = session
        self.h = {"X-OTX-API-KEY": api_key} if api_key else {}

    def check_domain(self, domain: str) -> Dict[str, Any]:
        r: Dict[str, Any] = {"source": "alienvault_otx", "available": False}
        if not self.key:
            r["error"] = "No API key configured"
            return r
        resp = _sg(self.s, f"{self.BASE}/indicators/domain/{domain}/general", headers=self.h)
        if resp and resp.status_code == 200:
            d = _safe_json(resp)
            if not d:
                r["error"] = "OTX response failed validation"
                return r
            r["available"] = True
            r["pulse_count"] = d.get("pulse_info", {}).get("count", 0)
            r["alexa_rank"] = d.get("alexa")
            r["validation"] = d.get("validation", [])
            pulses = d.get("pulse_info", {}).get("pulses", [])
            r["pulses"] = [
                {"name": p.get("name"), "description": (p.get("description") or "")[:200],
                 "created": p.get("created"), "tags": p.get("tags", [])[:10],
                 "adversary": p.get("adversary"),
                 "targeted_countries": p.get("targeted_countries", []),
                 "attack_ids": [a.get("display_name") for a in p.get("attack_ids", [])[:5]]}
                for p in pulses[:10]
            ]
        else:
            r["error"] = f"OTX error (HTTP {resp.status_code if resp else 'N/A'})"
        return r

    def check_ip(self, ip: str) -> Dict[str, Any]:
        r: Dict[str, Any] = {"source": "alienvault_otx_ip", "available": False}
        if not self.key:
            return r
        resp = _sg(self.s, f"{self.BASE}/indicators/IPv4/{ip}/general", headers=self.h)
        if resp and resp.status_code == 200:
            d = _safe_json(resp)
            if not d:
                return r
            r["available"] = True
            r["pulse_count"] = d.get("pulse_info", {}).get("count", 0)
            r["reputation"] = d.get("reputation")
            r["country"] = d.get("country_name")
            r["asn"] = d.get("asn")
            pulses = d.get("pulse_info", {}).get("pulses", [])
            r["pulses"] = [
                {"name": p.get("name"), "description": (p.get("description") or "")[:200],
                 "tags": p.get("tags", [])[:10], "adversary": p.get("adversary")}
                for p in pulses[:5]
            ]
        return r


# ===================================================================
# IPinfo.io — IP geolocation & ASN enrichment
# ===================================================================

class IPinfoClient:
    """Lightweight client for the IPinfo.io Lite API (free tier)."""

    def __init__(self, token: str, session: requests.Session):
        self.token = token
        self.s = session

    def lookup(self, ip: str) -> Dict[str, Any]:
        r: Dict[str, Any] = {"source": "ipinfo", "available": False}
        if not self.token:
            r["error"] = "No API token configured"
            return r
        resp = _sg(self.s, f"https://api.ipinfo.io/lite/{ip}",
                   params={"token": self.token},
                   headers={"Accept": "application/json"})
        if resp and resp.status_code == 200:
            d = _safe_json(resp)
            if not d:
                r["error"] = "IPinfo response failed validation"
                return r
            r.update({
                "available": True,
                "ip": d.get("ip"),
                "asn": d.get("asn"),
                "as_name": d.get("as_name"),
                "as_domain": d.get("as_domain"),
                "country_code": d.get("country_code"),
                "country": d.get("country"),
                "continent_code": d.get("continent_code"),
                "continent": d.get("continent"),
            })
        elif resp and resp.status_code == 429:
            r["error"] = "IPinfo rate limit exceeded"
        else:
            r["error"] = f"IPinfo error (HTTP {resp.status_code if resp else 'N/A'})"
        return r


# ===================================================================
# ThreatIntelAggregator
# ===================================================================

def _make_session() -> requests.Session:
    """Create a new session with ARGUS user-agent for thread-safe use."""
    s = requests.Session()
    s.headers.update({'User-Agent': 'ARGUS/1.0 Security Scanner'})
    return s


class ThreatIntelAggregator:
    def __init__(self, vt_key: str, abuseipdb_key: str, otx_key: str,
                 ipinfo_token: str = '', session: requests.Session = None):
        # Each client gets its own session for thread safety
        self.vt = VirusTotalClient(vt_key, _make_session())
        self.abuseipdb = AbuseIPDBClient(abuseipdb_key, _make_session())
        self.otx = AlienVaultOTXClient(otx_key, _make_session())
        self.ipinfo = IPinfoClient(ipinfo_token, _make_session())

    def analyze_url(self, url: str) -> Dict[str, Any]:
        with ThreadPoolExecutor(max_workers=1) as executor:
            futures = {
                "vt": executor.submit(self.vt.analyze_url, url),
            }
            results = {}
            for source, future in futures.items():
                try:
                    results[source] = future.result(timeout=10)
                except Exception as exc:
                    logger.debug("analyze_url/%s timed out: %s", source, exc)
                    results[source] = {"source": source, "available": False, "error": "timeout"}
        return results

    def analyze_domain(self, domain: str) -> Dict[str, Any]:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = {
                "vt": executor.submit(self.vt.get_domain_report, domain),
                "otx": executor.submit(self.otx.check_domain, domain),
            }
            results = {}
            for source, future in futures.items():
                try:
                    results[source] = future.result(timeout=10)
                except Exception as exc:
                    logger.debug("analyze_domain/%s timed out: %s", source, exc)
                    results[source] = {"source": source, "available": False, "error": "timeout"}
        return results

    def analyze_ip(self, ip: str) -> Dict[str, Any]:
        with ThreadPoolExecutor(max_workers=3) as executor:
            futures = {
                "abuseipdb": executor.submit(self.abuseipdb.check_ip, ip),
                "otx": executor.submit(self.otx.check_ip, ip),
                "ipinfo": executor.submit(self.ipinfo.lookup, ip),
            }
            results = {}
            for source, future in futures.items():
                try:
                    results[source] = future.result(timeout=10)
                except Exception as exc:
                    logger.debug("analyze_ip/%s timed out: %s", source, exc)
                    results[source] = {"source": source, "available": False, "error": "timeout"}
        return results

    def full_analysis(self, url: str, domain: str, ip: Optional[str] = None,
                      timeout: float = 15.0) -> Dict[str, Any]:
        """Run all three analysis tiers in parallel and merge results.
        A global *timeout* (seconds) caps the total wall-clock time.
        """
        combined: Dict[str, Any] = {"sources_queried": [], "sources_available": [], "verdict": "clean"}

        with ThreadPoolExecutor(max_workers=3) as executor:
            f_url = executor.submit(self.analyze_url, url)
            f_domain = executor.submit(self.analyze_domain, domain)
            f_ip = executor.submit(self.analyze_ip, ip) if ip else None

            try:
                url_results = f_url.result(timeout=timeout)
            except Exception:
                url_results = {}
            try:
                domain_results = f_domain.result(timeout=timeout)
            except Exception:
                domain_results = {}
            try:
                ip_results = f_ip.result(timeout=timeout) if f_ip else {}
            except Exception:
                ip_results = {}

        all_results = {}
        for bucket in (url_results, domain_results, ip_results):
            for key, val in bucket.items():
                source_name = val.get("source", key)
                all_results[source_name] = val
                combined["sources_queried"].append(source_name)
                if val.get("available"):
                    combined["sources_available"].append(source_name)

        combined["results"] = all_results

        # Derive unified verdict
        score, reasons = self.score_results(all_results)
        combined["threat_score"] = score
        combined["threat_reasons"] = reasons

        if score >= 10:
            combined["verdict"] = "malicious"
        elif score >= 5:
            combined["verdict"] = "suspicious"
        elif score >= 2:
            combined["verdict"] = "low_risk"
        else:
            combined["verdict"] = "clean"

        return combined

    @staticmethod
    def score_results(results: Dict[str, Any]) -> tuple:
        """Derive a numeric threat score and reasons from multi-source results."""
        score = 0
        reasons: List[str] = []

        # VirusTotal URL
        vt = results.get("virustotal", {})
        if vt.get("available") and not vt.get("scan_submitted"):
            stats = vt.get("stats", {})
            mal = stats.get("malicious", 0)
            sus = stats.get("suspicious", 0)
            if mal > 0:
                score += min(mal * 2, 15)
                reasons.append(f"VirusTotal: {vt.get('detection_ratio')} engines flagged as malicious")
            if sus > 0:
                score += min(sus, 5)
                reasons.append(f"VirusTotal: {sus} engines flagged as suspicious")
            rep = vt.get("reputation")
            if isinstance(rep, (int, float)) and rep < -5:
                score += 2
                reasons.append(f"VirusTotal: negative community reputation ({rep})")

        # VirusTotal Domain
        vtd = results.get("virustotal_domain", {})
        if vtd.get("available"):
            stats = vtd.get("stats", {})
            mal = stats.get("malicious", 0)
            if mal > 0:
                score += min(mal, 8)
                reasons.append(f"VirusTotal Domain: {mal} engines flagged domain as malicious")

        # AbuseIPDB
        adb = results.get("abuseipdb", {})
        if adb.get("available"):
            conf = adb.get("abuse_confidence_score", 0)
            if conf >= 80:
                score += 6
                reasons.append(f"AbuseIPDB: abuse confidence {conf}% ({adb.get('total_reports', 0)} reports)")
            elif conf >= 40:
                score += 3
                reasons.append(f"AbuseIPDB: moderate abuse confidence {conf}%")
            elif conf > 0:
                score += 1
                reasons.append(f"AbuseIPDB: low abuse confidence {conf}%")
            if adb.get("is_tor"):
                score += 2
                reasons.append("AbuseIPDB: IP is a known Tor exit node")

        # AlienVault OTX domain
        otx = results.get("alienvault_otx", {})
        if otx.get("available"):
            pc = otx.get("pulse_count", 0)
            if pc > 0:
                score += min(pc, 6)
                reasons.append(f"AlienVault OTX: domain appears in {pc} threat pulses")

        # AlienVault OTX IP
        otxi = results.get("alienvault_otx_ip", {})
        if otxi.get("available"):
            pc = otxi.get("pulse_count", 0)
            if pc > 0:
                score += min(pc, 4)
                reasons.append(f"AlienVault OTX: IP appears in {pc} threat pulses")

        # IPinfo — enrichment context (no direct score, but flag high-risk countries)
        ipi = results.get("ipinfo", {})
        if ipi.get("available"):
            cc = ipi.get("country_code", "")
            high_risk_countries = {"RU", "CN", "KP", "IR", "NG", "RO", "UA", "BY"}
            if cc in high_risk_countries:
                score += 1
                reasons.append(f"IPinfo: IP hosted in high-risk country ({ipi.get('country', cc)})")

        return score, reasons