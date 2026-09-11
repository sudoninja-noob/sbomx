"""SQLite-backed CVE response cache with TTL.

Keyed by (source, query) so NVD cpe queries and OSV package queries do not
collide. Stores the raw normalized CVE list as JSON.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import List, Optional

from ..core.component import CVE


class CveCache:
    def __init__(self, db_path: str = "cache.db", ttl_hours: int = 24):
        self.db_path = db_path
        self.ttl_seconds = ttl_hours * 3600
        if db_path not in (":memory:", "") and "mode=memory" not in db_path:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        # One connection for the cache's lifetime. The async pipeline runs in a
        # single thread, so check_same_thread can stay on its safe default.
        self._conn = sqlite3.connect(db_path)
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS cve_cache (
                source TEXT NOT NULL,
                query TEXT NOT NULL,
                payload TEXT NOT NULL,
                fetched_at INTEGER NOT NULL,
                PRIMARY KEY (source, query)
            )
            """
        )
        self._conn.commit()

    def get(self, source: str, query: str) -> Optional[List[CVE]]:
        """Return cached CVEs if present and not expired, else None."""
        row = self._conn.execute(
            "SELECT payload, fetched_at FROM cve_cache WHERE source=? AND query=?",
            (source, query),
        ).fetchone()
        if not row:
            return None
        payload, fetched_at = row
        if time.time() - fetched_at > self.ttl_seconds:
            return None
        return [CVE(**item) for item in json.loads(payload)]

    def put(self, source: str, query: str, cves: List[CVE]) -> None:
        payload = json.dumps([c.to_dict() for c in cves])
        self._conn.execute(
            "INSERT OR REPLACE INTO cve_cache (source, query, payload, fetched_at) "
            "VALUES (?, ?, ?, ?)",
            (source, query, payload, int(time.time())),
        )
        self._conn.commit()
