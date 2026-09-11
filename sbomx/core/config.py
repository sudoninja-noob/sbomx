"""Runtime configuration loaded from environment / .env."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _load_dotenv(path: str = ".env") -> None:
    """Minimal .env loader (no external dependency)."""
    p = Path(path)
    if not p.exists():
        return
    for line in p.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip('"').strip("'")
        os.environ.setdefault(key, val)


@dataclass
class Settings:
    """Central settings object."""

    nvd_api_key: str | None = None
    cache_db: str = "cache.db"
    cache_ttl_hours: int = 24
    offline: bool = False
    nvd_base_url: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    osv_base_url: str = "https://api.osv.dev/v1/query"
    request_timeout: float = 30.0

    @classmethod
    def load(cls, offline: bool = False, cache_db: str | None = None) -> "Settings":
        _load_dotenv()
        return cls(
            nvd_api_key=os.environ.get("NVD_API_KEY") or None,
            cache_db=cache_db or os.environ.get("SBOMX_CACHE_DB", "cache.db"),
            cache_ttl_hours=int(os.environ.get("SBOMX_CACHE_TTL_HOURS", "24")),
            offline=offline or os.environ.get("SBOMX_OFFLINE", "").lower() in ("1", "true", "yes"),
        )
