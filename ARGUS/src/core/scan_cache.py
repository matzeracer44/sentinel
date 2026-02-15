"""
ARGUS Scan History & Cache
Ephemeral in-memory cache — nothing is written to disk.
All data is lost when the session ends (by design).
"""

import json
import hashlib
import logging
import threading
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

logger = logging.getLogger('argus.scan_cache')


class ScanCache:
    """Thread-safe ephemeral scan result cache. Memory-only, no disk I/O."""

    MAX_MEMORY = 500          # max entries kept in RAM
    CACHE_TTL_SECONDS = 300   # 5 min — re-scan same URL after this

    def __init__(self):
        self._lock = threading.Lock()
        self._memory: Dict[str, Dict[str, Any]] = {}  # url_hash -> result
        self._history: List[Dict[str, Any]] = []       # ordered list
        logger.info('ScanCache initialised (ephemeral — no disk persistence)')

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get(self, url: str) -> Optional[Dict[str, Any]]:
        """Return cached result if fresh enough, else None."""
        key = self._key(url)
        with self._lock:
            entry = self._memory.get(key)
        if not entry:
            return None
        ts = entry.get('timestamp')
        if ts:
            try:
                scanned = datetime.fromisoformat(ts)
                if scanned.tzinfo is None:
                    scanned = scanned.replace(tzinfo=timezone.utc)
                age = (datetime.now(timezone.utc) - scanned).total_seconds()
                if age > self.CACHE_TTL_SECONDS:
                    return None
            except Exception:
                pass
        return entry

    def put(self, result: Dict[str, Any]) -> None:
        """Store a scan result in memory."""
        url = result.get('url', '')
        key = self._key(url)
        entry = {
            'url_hash': key,
            **result,
        }
        with self._lock:
            self._memory[key] = entry
            self._history.append({
                'url': url,
                'url_hash': key,
                'domain': result.get('domain', ''),
                'threat_level': result.get('threat_level', 'UNKNOWN'),
                'threat_score': result.get('threat_score', 0),
                'blocked': result.get('blocked', False),
                'sandbox': result.get('intel', {}).get('sandbox_active', False),
                'timestamp': result.get('timestamp', datetime.now(timezone.utc).isoformat()),
            })
            # Trim memory
            if len(self._memory) > self.MAX_MEMORY:
                oldest_key = next(iter(self._memory))
                del self._memory[oldest_key]

    def get_history(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Return recent scan history (newest first)."""
        with self._lock:
            items = list(reversed(self._history))
        return items[offset:offset + limit]

    def get_history_count(self) -> int:
        with self._lock:
            return len(self._history)

    def get_full_result(self, url_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve full cached result by hash."""
        with self._lock:
            return self._memory.get(url_hash)

    def clear(self) -> None:
        """Wipe all in-memory data."""
        with self._lock:
            self._memory.clear()
            self._history.clear()
        logger.info('ScanCache cleared')

    def export_json(self) -> str:
        """Export current session history as a JSON string (from memory)."""
        with self._lock:
            return json.dumps(self._history, indent=2, default=str)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _key(url: str) -> str:
        return hashlib.sha256(url.strip().encode()).hexdigest()[:16]
