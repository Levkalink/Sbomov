"""
KEV Checker — проверка CVE против CISA Known Exploited Vulnerabilities.
Использует локальный файл kev.json (обновляется при импорте).
"""
import json
import time
import urllib.request
from pathlib import Path

KEV_PATH = Path(__file__).parent / "kev.json"
KEV_URL  = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# In-memory cache: {cve_id: {name, vendor, due_date, ...}}
_kev_cache: dict[str, dict] | None = None
_kev_loaded_at: float = 0
_KEV_TTL = 86400  # rebuild from file max once per 24h


def _load_kev() -> dict[str, dict]:
    global _kev_cache, _kev_loaded_at
    now = time.time()
    if _kev_cache is not None and (now - _kev_loaded_at) < _KEV_TTL:
        return _kev_cache

    if not KEV_PATH.exists():
        _kev_cache = {}
        return _kev_cache

    try:
        with open(KEV_PATH, encoding="utf-8") as f:
            data = json.load(f)
        _kev_cache = {
            v["cveID"]: {
                "name":          v.get("vulnerabilityName", ""),
                "vendor":        v.get("vendorProject", ""),
                "product":       v.get("product", ""),
                "due_date":      v.get("dueDate", ""),
                "date_added":    v.get("dateAdded", ""),
                "short_desc":    v.get("shortDescription", ""),
                "required_action": v.get("requiredAction", ""),
            }
            for v in data.get("vulnerabilities", [])
        }
        _kev_loaded_at = now
        return _kev_cache
    except Exception:
        _kev_cache = {}
        return _kev_cache


def is_kev(cve_id: str) -> bool:
    return cve_id in _load_kev()


def get_kev_info(cve_id: str) -> dict | None:
    return _load_kev().get(cve_id)


def check_cve_list(cve_ids: list[str]) -> dict[str, dict]:
    """Returns dict of {cve_id: kev_info} for any CVEs that are in KEV."""
    kev = _load_kev()
    return {c: kev[c] for c in cve_ids if c in kev}


def get_stats() -> dict:
    kev = _load_kev()
    return {"total": len(kev), "loaded": bool(kev)}


def update_kev(timeout: int = 15) -> int:
    """Download fresh KEV from CISA. Returns count of entries."""
    try:
        req = urllib.request.urlopen(KEV_URL, timeout=timeout)
        data = json.loads(req.read())
        KEV_PATH.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
        # Invalidate cache
        global _kev_cache, _kev_loaded_at
        _kev_cache = None
        _kev_loaded_at = 0
        return len(data.get("vulnerabilities", []))
    except Exception as e:
        raise RuntimeError(f"Не удалось обновить KEV: {e}") from e
