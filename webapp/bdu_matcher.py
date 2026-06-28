"""
BDU Matcher — сопоставление компонентов SBOM с уязвимостями ФСТЭК БДУ.

Стратегия matching:
1. CVE cross-reference: если компонент имеет PURL и уязвимость имеет CVE ID
2. Vendor + Name + Version: нормализованное сравнение
3. Name-only: если vendor не указан (fallback)
"""
import json
import re
import sqlite3
from pathlib import Path
from typing import Optional

DB_PATH = Path(__file__).parent / "bdu.db"

# ═══════════════════════════════════════════════════════════════════════════
# Нормализация имён
# ═══════════════════════════════════════════════════════════════════════════

_STOP_WORDS = {
    "inc", "corp", "corporation", "ltd", "llc", "co", "the",
    "ооо", "зао", "пао", "ао", "нпо", "нии", "фгуп",
}

def normalize(s: str) -> str:
    """Нормализует строку для сравнения: lower, убирает спецсимволы."""
    if not s:
        return ""
    s = s.lower().strip()
    s = re.sub(r"[,.\-_/\\()®™«»]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    # Убираем стоп-слова только если остаётся что-то
    parts = [p for p in s.split() if p not in _STOP_WORDS]
    return " ".join(parts) if parts else s


def _extract_purl_info(purl: str) -> tuple[str, str, str]:
    """Извлекает (type, name, version) из PURL."""
    # pkg:type/namespace/name@version
    m = re.match(r"pkg:([^/]+)/(?:[^/]+/)?([^@?#]+)(?:@([^?#]*))?", purl or "")
    if m:
        return m.group(1), m.group(2).split("/")[-1], m.group(3) or ""
    return "", "", ""


def _version_match(sbom_ver: str, bdu_ver: str) -> bool:
    """Проверяет совпадение версий."""
    if not sbom_ver or not bdu_ver:
        return True   # если версия не указана — считаем потенциальным
    sv = sbom_ver.lower().strip()
    bv = bdu_ver.lower().strip()
    if sv == bv:
        return True
    # BDU часто пишет "до X.X" или "X.X и ниже"
    until = re.search(r"(?:до|before|up to|<=?)\s*([\d.]+)", bv)
    if until:
        try:
            from packaging.version import Version
            return Version(sv) <= Version(until.group(1))
        except Exception:
            return bv in sv or sv.startswith(bv.split(".")[0])
    # Проверка на major.minor
    sv_parts = sv.split(".")[:2]
    bv_parts = bv.split(".")[:2]
    return sv_parts == bv_parts or sv.startswith(bv) or bv.startswith(sv)


# ═══════════════════════════════════════════════════════════════════════════
# Основная функция поиска
# ═══════════════════════════════════════════════════════════════════════════

def match_component(
    name: str,
    version: str = "",
    vendor: str = "",
    purl: str = "",
    cve_ids: list[str] | None = None,
    db_path: Path = DB_PATH,
    limit: int = 20,
) -> list[dict]:
    """
    Ищет уязвимости BDU для одного компонента SBOM.
    Возвращает список найденных уязвимостей.
    """
    if not db_path.exists():
        return []

    con = sqlite3.connect(db_path)
    con.row_factory = sqlite3.Row
    results: dict[str, dict] = {}   # bdu_id → record

    name_n   = normalize(name)
    vendor_n = normalize(vendor)
    _, purl_name, purl_ver = _extract_purl_info(purl)
    purl_name_n = normalize(purl_name)

    # ── 1. CVE cross-reference (самый точный) ───────────────────────────────
    all_cve_ids = list(cve_ids or [])
    # Извлекаем CVE из PURL если есть
    if not all_cve_ids and purl:
        all_cve_ids = re.findall(r"CVE-\d{4}-\d+", purl, re.I)

    if all_cve_ids:
        placeholders = ",".join("?" * len(all_cve_ids))
        rows = con.execute(f"""
            SELECT v.*, GROUP_CONCAT(DISTINCT c.cve_id) as cve_ids,
                   GROUP_CONCAT(DISTINCT cw.cwe_id) as cwes
            FROM vulnerabilities v
            JOIN cve_mapping c ON c.vul_id = v.id
            LEFT JOIN cwe_mapping cw ON cw.vul_id = v.id
            WHERE c.cve_id IN ({placeholders})
            GROUP BY v.id
            LIMIT ?
        """, all_cve_ids + [limit]).fetchall()
        for r in rows:
            rec = _row_to_dict(r, match_type="cve", matched_by=f"CVE: {r['cve_ids']}")
            results[r["bdu_id"]] = rec

    # ── 2. Vendor + Name matching ────────────────────────────────────────────
    search_names = list({n for n in [name_n, purl_name_n] if n})
    for sname in search_names:
        if not sname:
            continue
        # Ищем по нормализованному имени
        rows = con.execute("""
            SELECT DISTINCT v.*, GROUP_CONCAT(DISTINCT c.cve_id) as cve_ids,
                   GROUP_CONCAT(DISTINCT cw.cwe_id) as cwes,
                   a.vendor, a.version as soft_version
            FROM vulnerabilities v
            JOIN affected_software a ON a.vul_id = v.id
            LEFT JOIN cve_mapping c ON c.vul_id = v.id
            LEFT JOIN cwe_mapping cw ON cw.vul_id = v.id
            WHERE a.name_norm LIKE ?
            GROUP BY v.id
            LIMIT ?
        """, (f"%{sname}%", limit * 3)).fetchall()

        for r in rows:
            if r["bdu_id"] in results:
                continue
            # Vendor filter — если vendor известен, проверяем совпадение
            if vendor_n and r["vendor"]:
                r_vendor_n = normalize(r["vendor"])
                # Хотя бы одно слово должно совпадать
                sv = set(vendor_n.split())
                rv = set(r_vendor_n.split())
                if sv and rv and sv.isdisjoint(rv):
                    continue
            # Version filter
            soft_ver = r["soft_version"] or ""
            if version and soft_ver and not _version_match(version, soft_ver):
                continue
            results[r["bdu_id"]] = _row_to_dict(
                r, match_type="name",
                matched_by=f"name: {sname}" + (f", vendor: {vendor_n}" if vendor_n else "")
            )

    con.close()

    # Сортируем: сначала CVE-match, потом по CVSS desc
    out = sorted(
        results.values(),
        key=lambda x: (
            0 if x["match_type"] == "cve" else 1,
            -(x["cvss_score"] or 0),
        )
    )
    return out[:limit]


def _row_to_dict(row: sqlite3.Row, match_type: str = "name", matched_by: str = "") -> dict:
    r = dict(row)
    return {
        "bdu_id":         r.get("bdu_id", ""),
        "name":           r.get("name", ""),
        "description":    (r.get("description") or "")[:500],
        "severity":       r.get("severity", "unknown"),
        "cvss_score":     r.get("cvss_score"),
        "cvss_vector":    r.get("cvss_vector", ""),
        "has_exploit":    bool(r.get("has_exploit")),
        "public_exploit": bool(r.get("public_exploit")),
        "exploit_raw":    r.get("exploit_raw", ""),
        "fix_status":     r.get("fix_status", ""),
        "solution":       (r.get("solution") or "")[:400],
        "vul_class":      r.get("vul_class", ""),
        "pub_date":       r.get("pub_date", ""),
        "cve_ids":        r.get("cve_ids", "").split(",") if r.get("cve_ids") else [],
        "cwes":           r.get("cwes", "").split(",") if r.get("cwes") else [],
        "match_type":     match_type,
        "matched_by":     matched_by,
        "bdu_url":        f"https://bdu.fstec.ru/vul/{r.get('bdu_id','').replace('BDU:','')}",
    }


# ═══════════════════════════════════════════════════════════════════════════
# Scan целого SBOM
# ═══════════════════════════════════════════════════════════════════════════

def scan_sbom(sbom_path: Path, db_path: Path = DB_PATH) -> dict:
    """
    Сканирует CycloneDX JSON SBOM против базы BDU.
    Возвращает отчёт с найденными уязвимостями по компонентам.
    """
    with open(sbom_path, encoding="utf-8") as f:
        sbom = json.load(f)

    components = sbom.get("components", [])
    results = []
    stats = {"critical": 0, "high": 0, "medium": 0, "low": 0,
             "with_exploit": 0, "total_vulns": 0, "affected_components": 0}

    for comp in components:
        name    = comp.get("name", "")
        version = comp.get("version", "")
        purl    = comp.get("purl", "")
        # Supplier/vendor
        supplier = ""
        if comp.get("supplier"):
            supplier = comp["supplier"].get("name", "")
        elif comp.get("publisher"):
            supplier = comp["publisher"]
        elif comp.get("author"):
            supplier = comp["author"]

        vulns = match_component(
            name=name, version=version,
            vendor=supplier, purl=purl,
            db_path=db_path,
        )

        if vulns:
            stats["affected_components"] += 1
            for v in vulns:
                stats["total_vulns"] += 1
                stats[v["severity"]] = stats.get(v["severity"], 0) + 1
                if v["has_exploit"]:
                    stats["with_exploit"] += 1

            results.append({
                "component": {
                    "name":    name,
                    "version": version,
                    "purl":    purl,
                    "type":    comp.get("type", ""),
                },
                "vulnerabilities": vulns,
            })

    # Сортируем: сначала критические
    SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "unknown": 4}
    results.sort(key=lambda x: min(
        SEV_ORDER.get(v["severity"], 4) for v in x["vulnerabilities"]
    ))

    return {
        "stats":      stats,
        "components": results,
        "total_components_scanned": len(components),
    }


def get_stats(db_path: Path = DB_PATH) -> dict:
    """Возвращает статистику по базе BDU."""
    if not db_path.exists():
        return {"loaded": False}
    try:
        con = sqlite3.connect(db_path)
        total = con.execute("SELECT COUNT(*) FROM vulnerabilities").fetchone()[0]
        by_sev = dict(con.execute(
            "SELECT severity, COUNT(*) FROM vulnerabilities GROUP BY severity"
        ).fetchall())
        exploits = con.execute(
            "SELECT COUNT(*) FROM vulnerabilities WHERE has_exploit=1"
        ).fetchone()[0]
        meta = dict(con.execute("SELECT key, value FROM import_meta").fetchall())
        con.close()
        return {
            "loaded": True,
            "total": total,
            "by_severity": by_sev,
            "with_exploit": exploits,
            "imported_at": meta.get("imported_at", ""),
            "source": meta.get("source", ""),
        }
    except Exception as e:
        return {"loaded": False, "error": str(e)}
