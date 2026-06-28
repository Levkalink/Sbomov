"""
EPSS Fetcher — Exploit Prediction Scoring System (FIRST.org).
Бесплатный API, не требует авторизации.
Возвращает вероятность эксплуатации в течение 30 дней и перцентиль.
"""
import json
import time
import urllib.request
import urllib.parse
from typing import Optional

_BASE = "https://api.first.org/data/v1/epss"

# Simple in-process cache: {cve_id: {score, percentile, date, fetched_at}}
_cache: dict[str, dict] = {}
_TTL = 3600  # 1 hour


def get_epss(cve_ids: list[str]) -> dict[str, dict]:
    """
    Fetch EPSS scores for a list of CVE IDs.
    Returns {cve_id: {score: float, percentile: float, date: str}} for found CVEs.
    Silently ignores network errors.
    """
    if not cve_ids:
        return {}

    now = time.time()

    # Split: cached vs needs fetch
    result: dict[str, dict] = {}
    to_fetch: list[str] = []
    for cid in cve_ids:
        cached = _cache.get(cid)
        if cached and (now - cached.get("fetched_at", 0)) < _TTL:
            result[cid] = cached
        else:
            to_fetch.append(cid)

    if not to_fetch:
        return result

    # Batch: FIRST API accepts up to 100 CVEs per request
    BATCH = 100
    for i in range(0, len(to_fetch), BATCH):
        batch = to_fetch[i:i + BATCH]
        try:
            url = _BASE + "?" + urllib.parse.urlencode([("cve", c) for c in batch])
            req = urllib.request.urlopen(url, timeout=8)
            data = json.loads(req.read())
            for item in data.get("data", []):
                cve_id = item.get("cve", "")
                entry = {
                    "score":       float(item.get("epss", 0)),
                    "percentile":  float(item.get("percentile", 0)),
                    "date":        item.get("date", ""),
                    "fetched_at":  now,
                }
                _cache[cve_id] = entry
                result[cve_id] = entry
        except Exception:
            pass  # Network unavailable — return what we have

    return result


def enrich_cve_list(cve_ids: list[str]) -> dict:
    """
    Returns summary enrichment for a list of CVE IDs:
    - per-CVE EPSS scores
    - max_epss: highest score in list
    - high_epss_cves: CVEs with epss > 0.1 (top ~10%)
    """
    scores = get_epss(cve_ids)
    if not scores:
        return {"epss_by_cve": {}, "max_epss": None, "high_epss_cves": []}

    max_epss = max((v["score"] for v in scores.values()), default=None)
    high = [cid for cid, v in scores.items() if v["score"] > 0.1]
    return {
        "epss_by_cve":    {k: v["score"] for k, v in scores.items()},
        "max_epss":       round(max_epss, 4) if max_epss else None,
        "high_epss_cves": high,
    }


def priority_score(cvss: Optional[float], epss: Optional[float],
                   in_kev: bool, has_exploit: bool) -> float:
    """
    Composite priority score 0-100, inspired by Red-Lycoris FindingScore:
      40% CVSS  (0-10 → 0-40)
      30% EPSS  (0-1  → 0-30)
      20% KEV   (binary bonus)
      10% BDU exploit existence
    """
    score = 0.0
    if cvss is not None:
        score += min(cvss / 10.0, 1.0) * 40
    if epss is not None:
        score += min(epss, 1.0) * 30
    if in_kev:
        score += 20
    if has_exploit:
        score += 10
    return round(score, 1)
