"""
CycloneDX VEX (Vulnerability Exploitability eXchange) generator.
Встраивает результаты BDU/Grype/Trivy сканирования в секцию `vulnerabilities` SBOM.
Формат: CycloneDX 1.4+ JSON.
"""
import datetime
import json
import uuid
from pathlib import Path


_STATUS_MAP = {
    "open":           "in_triage",
    "confirmed":      "affected",
    "resolved":       "resolved",
    "risk_accepted":  "not_affected",
    "false_positive": "not_affected",
}

_JUSTIFICATION_MAP = {
    "risk_accepted":  "requires_configuration",
    "false_positive": "code_not_reachable",
}


def generate_vex_section(scan_result: dict) -> list[dict]:
    """
    Конвертирует результат scan_sbom() в список CycloneDX Vulnerability objects.
    """
    vulns = []
    now = datetime.datetime.utcnow().isoformat() + "Z"

    for comp_entry in scan_result.get("components", []):
        comp = comp_entry.get("component", {})
        purl = comp.get("purl", "")
        name = comp.get("name", "")
        version = comp.get("version", "")

        affects_ref = []
        if purl:
            affects_ref = [{"ref": purl}]
        elif name:
            affects_ref = [{"ref": f"{name}@{version}" if version else name}]

        for v in comp_entry.get("vulnerabilities", []):
            bdu_id = v.get("bdu_id", "")
            cve_ids = v.get("cve_ids", [])
            status = v.get("status", "open")
            cvss = v.get("cvss_score")

            # Build id list: use first CVE or BDU id
            primary_id = cve_ids[0] if cve_ids else bdu_id

            vex_obj: dict = {
                "id": primary_id,
                "source": {
                    "name": "БДУ ФСТЭК",
                    "url": v.get("bdu_url", "https://bdu.fstec.ru"),
                },
                "ratings": [],
                "description": v.get("description", "")[:500],
                "detail": v.get("solution", "")[:300],
                "recommendation": v.get("fix_status", ""),
                "created": now,
                "updated": now,
                "affects": [{"ref": r["ref"], "versions": [{"version": version}]}
                            for r in affects_ref],
                "analysis": {
                    "state": _STATUS_MAP.get(status, "in_triage"),
                },
                "properties": [
                    {"name": "bdu:id", "value": bdu_id},
                    {"name": "bdu:has_exploit", "value": str(v.get("has_exploit", False))},
                    {"name": "bdu:public_exploit", "value": str(v.get("public_exploit", False))},
                    {"name": "bdu:priority_score", "value": str(v.get("priority_score", ""))},
                    {"name": "sbom:match_type", "value": v.get("match_type", "")},
                ],
            }

            if justification := _JUSTIFICATION_MAP.get(status):
                vex_obj["analysis"]["justification"] = justification

            if cvss is not None:
                vex_obj["ratings"].append({
                    "source": {"name": "БДУ ФСТЭК"},
                    "score": cvss,
                    "severity": v.get("severity", "unknown"),
                    "method": "CVSSv3",
                    "vector": v.get("cvss_vector", ""),
                })

            # Additional CVE ids as advisories
            advisories = []
            for cve in cve_ids:
                advisories.append({"title": cve,
                                   "url": f"https://nvd.nist.gov/vuln/detail/{cve}"})
            if advisories:
                vex_obj["advisories"] = advisories

            vulns.append(vex_obj)

    return vulns


def embed_vex_into_sbom(sbom_path: Path, scan_result: dict, out_path: Path | None = None) -> Path:
    """
    Встраивает VEX-данные в CycloneDX SBOM, добавляя секцию `vulnerabilities`.
    Возвращает путь к обновлённому файлу.
    """
    with open(sbom_path, encoding="utf-8") as f:
        sbom = json.load(f)

    vex_vulns = generate_vex_section(scan_result)
    sbom["vulnerabilities"] = vex_vulns

    # Add VEX tag to metadata properties
    props = sbom.get("metadata", {}).get("properties") or []
    props.append({
        "name": "sbom:vex_embedded",
        "value": str(len(vex_vulns)),
    })
    props.append({
        "name": "sbom:vex_generated_at",
        "value": datetime.datetime.utcnow().isoformat() + "Z",
    })
    if "metadata" not in sbom:
        sbom["metadata"] = {}
    sbom["metadata"]["properties"] = props

    out = out_path or sbom_path.parent / (sbom_path.stem + "-vex.json")
    with open(out, "w", encoding="utf-8") as f:
        json.dump(sbom, f, ensure_ascii=False, indent=2)

    return out
