"""
Парсеры результатов внешних SCA/vulnerability сканеров.
Поддерживает: Grype JSON, Trivy JSON, OSV-Scanner JSON, SARIF 2.1.0, Generic JSON.
Нормализует в единую Finding-модель.
"""
import hashlib
import json
import re
from pathlib import Path
from typing import Any

# ═══════════════════════════════════════════════════════════════════════════
# Finding model
# ═══════════════════════════════════════════════════════════════════════════

def make_finding(
    source_type: str,
    cve_ids: list[str],
    component: str,
    component_version: str,
    severity: str,
    title: str,
    description: str = "",
    fixed_version: str = "",
    purl: str = "",
    cvss_score: float | None = None,
    cwe_ids: list[str] | None = None,
    file_path: str = "",
) -> dict:
    """Create normalized vulnerability finding dict."""
    fp = hashlib.sha256(
        ("".join(cve_ids) + component + component_version + "sca").encode()
    ).hexdigest()
    return {
        "kind":               "sca",
        "source_type":        source_type,
        "fingerprint":        fp,
        "cve_ids":            cve_ids,
        "cwe_ids":            cwe_ids or [],
        "component":          component,
        "component_version":  component_version,
        "fixed_version":      fixed_version,
        "purl":               purl,
        "severity":           _norm_severity(severity),
        "title":              title,
        "description":        description[:800],
        "file_path":          file_path,
        "cvss_score":         cvss_score,
        "status":             "open",
    }


def _norm_severity(s: str) -> str:
    s = (s or "").lower().strip()
    if s in ("critical", "high", "medium", "low", "info"):
        return s
    m = {"negligible": "low", "moderate": "medium", "important": "high",
         "severe": "high", "unknown": "medium"}.get(s, "medium")
    return m


# ═══════════════════════════════════════════════════════════════════════════
# Auto-detect format
# ═══════════════════════════════════════════════════════════════════════════

def detect_and_parse(data: bytes) -> tuple[str, list[dict]]:
    """
    Auto-detects scanner format and returns (format_name, [findings]).
    Raises ValueError if format unrecognized.
    """
    try:
        obj = json.loads(data)
    except Exception as e:
        raise ValueError(f"Not valid JSON: {e}")

    # Grype: has "matches" + "descriptor"
    if isinstance(obj, dict) and "matches" in obj and "descriptor" in obj:
        return "grype", parse_grype(obj)

    # Trivy: has "SchemaVersion" + "Results"
    if isinstance(obj, dict) and "SchemaVersion" in obj and "Results" in obj:
        return "trivy", parse_trivy(obj)

    # OSV-Scanner: has "results" list with "packages" + "vulnerabilities"
    if isinstance(obj, dict) and "results" in obj:
        results = obj["results"]
        if isinstance(results, list) and results and "packages" in results[0]:
            return "osv", parse_osv(obj)

    # SARIF 2.1.0: has "$schema" or "version":"2.1.0" + "runs"
    if isinstance(obj, dict) and "runs" in obj:
        return "sarif", parse_sarif(obj)

    # Generic: array of objects with "cve" / "vulnerability"
    if isinstance(obj, list) and obj and isinstance(obj[0], dict):
        if any(k in obj[0] for k in ("cve", "vulnerability", "cveId", "vuln_id")):
            return "generic", parse_generic(obj)

    raise ValueError("Unsupported format: no parser matched")


# ═══════════════════════════════════════════════════════════════════════════
# Grype JSON parser
# ═══════════════════════════════════════════════════════════════════════════

def parse_grype(obj: dict) -> list[dict]:
    findings = []
    for match in obj.get("matches", []):
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})

        vid = vuln.get("id", "")
        cve_ids = [vid] if vid.upper().startswith("CVE-") else []
        related = [r.get("id", "") for r in vuln.get("relatedVulnerabilities", [])
                   if r.get("id", "").upper().startswith("CVE-")]
        cve_ids = list(set(cve_ids + related))

        severity = vuln.get("severity", "unknown")
        cvss_score = None
        for c in vuln.get("cvss", []):
            if c.get("version", "").startswith("3"):
                cvss_score = c.get("metrics", {}).get("baseScore")
                break

        fix_versions = vuln.get("fix", {}).get("versions", [])
        fixed = fix_versions[0] if fix_versions else ""

        purl = artifact.get("purl", "")
        locations = artifact.get("locations", [])
        file_path = locations[0].get("path", "") if locations else ""

        title = f"{vid} in {artifact.get('name', '')}" if vid else f"Vulnerability in {artifact.get('name', '')}"

        findings.append(make_finding(
            source_type="grype",
            cve_ids=cve_ids,
            component=artifact.get("name", ""),
            component_version=artifact.get("version", ""),
            severity=severity,
            title=title,
            description=vuln.get("description", ""),
            fixed_version=fixed,
            purl=purl,
            cvss_score=cvss_score,
            cwe_ids=[c for c in vuln.get("cweIds", []) if c],
            file_path=file_path,
        ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Trivy JSON parser
# ═══════════════════════════════════════════════════════════════════════════

def parse_trivy(obj: dict) -> list[dict]:
    findings = []
    for result in obj.get("Results", []):
        for vuln in result.get("Vulnerabilities", []):
            vid = vuln.get("VulnerabilityID", "")
            cve_ids = [vid] if vid.upper().startswith("CVE-") else []

            cvss_score = None
            cvss_data = vuln.get("CVSS", {})
            for source_data in cvss_data.values():
                if "V3Score" in source_data:
                    cvss_score = source_data["V3Score"]
                    break

            pkg_id = vuln.get("PkgIdentifier", {})
            purl = pkg_id.get("PURL", "")

            title = vuln.get("Title") or f"{vid} in {vuln.get('PkgName', '')}"

            findings.append(make_finding(
                source_type="trivy",
                cve_ids=cve_ids,
                component=vuln.get("PkgName", ""),
                component_version=vuln.get("InstalledVersion", ""),
                severity=vuln.get("Severity", "unknown"),
                title=title,
                description=vuln.get("Description", ""),
                fixed_version=vuln.get("FixedVersion", ""),
                purl=purl,
                cvss_score=cvss_score,
                cwe_ids=vuln.get("CweIDs", []),
                file_path=vuln.get("PkgPath", result.get("Target", "")),
            ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# OSV-Scanner JSON parser
# ═══════════════════════════════════════════════════════════════════════════

def parse_osv(obj: dict) -> list[dict]:
    findings = []
    for result in obj.get("results", []):
        for pkg in result.get("packages", []):
            pkg_info = pkg.get("package", {})
            purl = pkg_info.get("purl", "")
            name = pkg_info.get("name", "")
            version = pkg_info.get("version", "")
            for vuln in pkg.get("vulnerabilities", []):
                vid = vuln.get("id", "")
                aliases = vuln.get("aliases", [])
                cve_ids = [a for a in [vid] + aliases if a.upper().startswith("CVE-")]

                severity = "medium"
                cvss_score = None
                for sev in vuln.get("severity", []):
                    score_str = sev.get("score", "")
                    if score_str:
                        try:
                            cvss_score = float(score_str)
                            severity = _cvss_to_severity(cvss_score)
                        except Exception:
                            pass
                        break

                affected = vuln.get("affected", [{}])[0]
                ranges = affected.get("ranges", [])
                fixed_version = ""
                for r in ranges:
                    for event in r.get("events", []):
                        if "fixed" in event:
                            fixed_version = event["fixed"]
                            break

                findings.append(make_finding(
                    source_type="osv",
                    cve_ids=cve_ids,
                    component=name,
                    component_version=version,
                    severity=severity,
                    title=vuln.get("summary") or f"{vid} in {name}",
                    description=vuln.get("details", ""),
                    fixed_version=fixed_version,
                    purl=purl,
                    cvss_score=cvss_score,
                ))
    return findings


def _cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "critical"
    if score >= 7.0: return "high"
    if score >= 4.0: return "medium"
    return "low"


# ═══════════════════════════════════════════════════════════════════════════
# SARIF 2.1.0 parser (SCA rules only)
# ═══════════════════════════════════════════════════════════════════════════

def parse_sarif(obj: dict) -> list[dict]:
    findings = []
    for run in obj.get("runs", []):
        tool = run.get("tool", {}).get("driver", {})
        source_type = tool.get("name", "sarif").lower()[:20]

        rules: dict[str, Any] = {}
        for rule in tool.get("rules", []):
            rules[rule.get("id", "")] = rule

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules.get(rule_id, {})

            # Extract CVE from rule id or help text
            cve_ids = re.findall(r"CVE-\d{4}-\d+", json.dumps(rule), re.I)
            cve_ids += re.findall(r"CVE-\d{4}-\d+", result.get("message", {}).get("text", ""), re.I)
            cve_ids = list(set(cve_ids))

            severity = "medium"
            level = result.get("level", "warning")
            if level == "error": severity = "high"
            elif level == "note": severity = "low"

            # Component from properties
            props = result.get("properties", {})
            component = props.get("component", props.get("package", ""))
            component_version = props.get("version", "")
            purl = props.get("purl", "")

            locations = result.get("locations", [])
            file_path = ""
            if locations:
                loc = locations[0].get("physicalLocation", {})
                file_path = loc.get("artifactLocation", {}).get("uri", "")

            title = (rule.get("shortDescription", {}).get("text")
                     or result.get("message", {}).get("text", rule_id or "SARIF finding")[:200])

            findings.append(make_finding(
                source_type=source_type,
                cve_ids=cve_ids,
                component=component,
                component_version=component_version,
                severity=severity,
                title=title,
                description=rule.get("fullDescription", {}).get("text", "")[:500],
                purl=purl,
                file_path=file_path,
            ))
    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Generic JSON parser
# ═══════════════════════════════════════════════════════════════════════════

def parse_generic(obj: list[dict]) -> list[dict]:
    findings = []
    for item in obj:
        cve_id = item.get("cve") or item.get("cveId") or item.get("vuln_id", "")
        cve_ids = [cve_id] if cve_id else []
        findings.append(make_finding(
            source_type="generic",
            cve_ids=cve_ids,
            component=item.get("package") or item.get("component", ""),
            component_version=item.get("version", ""),
            severity=item.get("severity", "medium"),
            title=item.get("title") or item.get("name") or cve_id or "Vulnerability",
            description=item.get("description", ""),
            fixed_version=item.get("fixedVersion") or item.get("fixed_version", ""),
            purl=item.get("purl", ""),
            cvss_score=item.get("cvss") or item.get("cvssScore"),
        ))
    return findings
