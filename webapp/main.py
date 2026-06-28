"""SBOM Automation Web UI — FastAPI backend"""
import asyncio
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
import zipfile
from pathlib import Path
from typing import Optional

import aiofiles
from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks, Body
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

# BDU modules
sys.path.insert(0, str(Path(__file__).parent))
try:
    from bdu_parser  import build_db, db_exists, get_meta, DB_PATH as BDU_DB
    from bdu_matcher import scan_sbom, get_stats, match_component
    BDU_AVAILABLE = True
except ImportError:
    BDU_AVAILABLE = False
    BDU_DB = Path(__file__).parent / "bdu.db"

try:
    from vuln_importer import detect_and_parse as import_vuln_file
    from vex_generator import embed_vex_into_sbom
    from xlsx_exporter import export_bdu_scan
    IMPORTERS_OK = True
except ImportError:
    IMPORTERS_OK = False

try:  # EPSS + KEV enrichment (optional, requires network for EPSS)
    from kev_checker import check_cve_list, get_stats as get_kev_stats, update_kev  # noqa: F401
    from epss_fetcher import enrich_cve_list, priority_score as epss_priority  # noqa: F401
    KEV_AVAILABLE = True
except ImportError:
    KEV_AVAILABLE = False

import job_store

BDU_JOBS: dict[str, dict] = {}

# ─── Paths ──────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
CHECKER_DIR = BASE_DIR.parent / "sbom-checker-master"
JOBS_DIR    = BASE_DIR / "jobs"
JOBS_DIR.mkdir(exist_ok=True)

PYTHON     = sys.executable
CHECKER_PY = CHECKER_DIR / "sbom-checker.py"
UPDATER_PY = CHECKER_DIR / "sbom-updater.py"
TO_CSV_PY  = CHECKER_DIR / "sbom-to-csv.py"
TO_ODT_PY  = CHECKER_DIR / "sbom-to-odt.py"

CHECKER_ENV = {**os.environ, "PYTHONPATH": str(CHECKER_DIR)}

# In-memory log cache for running jobs (flushed to SQLite periodically)
_LOG_CACHE: dict[str, list[str]] = {}
_LOG_CURSOR: dict[str, int] = {}

job_store.init(BASE_DIR / "jobs.db")

app = FastAPI(title="SBOM Automation")
app.mount("/static", StaticFiles(directory=BASE_DIR / "static"), name="static")


# ═══════════════════════════════════════════════════════════════════════════
# UI
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/", response_class=HTMLResponse)
async def root():
    return (BASE_DIR / "templates" / "index.html").read_text(encoding="utf-8")


# ═══════════════════════════════════════════════════════════════════════════
# File System Browser
# ═══════════════════════════════════════════════════════════════════════════
BROWSE_ROOTS = ["/root", "/home", "/opt", "/srv", "/tmp", "/var/projects"]

@app.get("/api/browse")
async def browse(path: str = "/root"):
    path = os.path.normpath(path)
    allowed = path == "/" or any(path == r or path.startswith(r + "/") for r in BROWSE_ROOTS)
    if not allowed:
        raise HTTPException(403, "Путь не разрешён")
    if not os.path.isdir(path):
        raise HTTPException(404, "Директория не найдена")
    entries = []
    try:
        for name in sorted(os.listdir(path)):
            if name.startswith("."):
                continue
            full = os.path.join(path, name)
            try:
                is_dir = os.path.isdir(full)
                size = os.path.getsize(full) if not is_dir else 0
                entries.append({
                    "name": name, "path": full,
                    "is_dir": is_dir, "size": size,
                    "has_children": is_dir and any(
                        not n.startswith(".") for n in os.listdir(full)
                    ) if is_dir else False,
                })
            except (PermissionError, OSError):
                pass
    except PermissionError:
        raise HTTPException(403, "Нет доступа к директории")
    return {"path": path, "parent": str(Path(path).parent) if path != "/" else None, "entries": entries}


# ═══════════════════════════════════════════════════════════════════════════
# Upload
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/api/upload")
async def upload_file(file: UploadFile = File(...)):
    name = file.filename or "upload"
    upload_dir = JOBS_DIR / f"upload_{uuid.uuid4().hex[:8]}"
    upload_dir.mkdir()
    dest = upload_dir / name

    async with aiofiles.open(dest, "wb") as f:
        await f.write(await file.read())

    extracted = None
    fname = name.lower()
    if fname.endswith(".tar.gz") or fname.endswith(".tgz") or fname.endswith(".tar.bz2") \
       or fname.endswith(".tar.xz") or fname.endswith(".tar"):
        extracted = upload_dir / "extracted"
        extracted.mkdir()
        with tarfile.open(dest) as t:
            t.extractall(extracted)
    elif fname.endswith(".zip"):
        extracted = upload_dir / "extracted"
        extracted.mkdir()
        with zipfile.ZipFile(dest, "r") as z:
            z.extractall(extracted)
    elif fname.endswith(".gz") and not fname.endswith(".tar.gz"):
        import gzip
        out = upload_dir / name[:-3]
        with gzip.open(dest, "rb") as gz, open(out, "wb") as o:
            shutil.copyfileobj(gz, o)

    if extracted:
        children = [c for c in extracted.iterdir() if not c.name.startswith(".")]
        if len(children) == 1 and children[0].is_dir():
            extracted = children[0]

    is_sbom = fname.endswith(".json")
    return {
        "upload_path":   str(dest),
        "project_path":  str(extracted or upload_dir),
        "filename":      name,
        "is_sbom":       is_sbom,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Language Detection
# ═══════════════════════════════════════════════════════════════════════════

# (cdxgen_type, display_name, icon, root_markers, glob_markers, recursive_glob)
# root_markers: files to check directly in project root
# glob_markers: glob patterns to search recursively
_SKIP_DIRS = {"node_modules", ".git", "vendor", "target", "__pycache__",
              ".venv", "venv", "build", "dist", ".cache"}

LANGUAGE_SPECS = [
    {
        "type": "go",
        "name": "Go",
        "icon": "🐹",
        "root": ["go.mod"],
        "glob": [],
    },
    {
        "type": "python",
        "name": "Python",
        "icon": "🐍",
        "root": ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile", "setup.cfg", "poetry.lock"],
        "glob": ["**/requirements*.txt", "**/pyproject.toml"],
    },
    {
        "type": "js",
        "name": "Node.js",
        "icon": "🟩",
        "root": ["package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"],
        "glob": [],
    },
    {
        "type": "java",
        "name": "Java/Maven",
        "icon": "☕",
        "root": ["pom.xml"],
        "glob": ["**/pom.xml"],
    },
    {
        "type": "gradle",
        "name": "Gradle",
        "icon": "🐘",
        "root": ["build.gradle", "build.gradle.kts", "settings.gradle"],
        "glob": ["**/build.gradle", "**/build.gradle.kts"],
    },
    {
        "type": "rust",
        "name": "Rust",
        "icon": "🦀",
        "root": ["Cargo.toml"],
        "glob": ["**/Cargo.toml"],
    },
    {
        "type": "dotnet",
        "name": ".NET",
        "icon": "🔷",
        "root": [],
        "glob": ["**/*.csproj", "**/*.sln", "**/*.fsproj"],
    },
    {
        "type": "php",
        "name": "PHP",
        "icon": "🐘",
        "root": ["composer.json"],
        "glob": ["**/composer.json"],
    },
    {
        "type": "ruby",
        "name": "Ruby",
        "icon": "💎",
        "root": ["Gemfile"],
        "glob": ["**/Gemfile"],
    },
    {
        "type": "c",
        "name": "C/C++",
        "icon": "⚙️",
        "root": ["CMakeLists.txt", "conanfile.txt", "conanfile.py", "vcpkg.json", "meson.build", "Makefile"],
        "glob": ["**/CMakeLists.txt", "**/conanfile.txt", "**/vcpkg.json", "**/meson.build",
                 "**/*.c", "**/*.cpp", "**/*.h", "**/*.cc", "**/*.cxx"],
    },
]


def _detect_languages(project_path: str) -> list[dict]:
    """
    Scans project directory for language/ecosystem markers.
    Checks root files first, then recurses into subdirectories.
    Returns detected ecosystems with cdxgen type and display info.
    """
    p = Path(project_path)
    found: dict[str, dict] = {}

    def _is_skipped(path: Path) -> bool:
        return any(part in _SKIP_DIRS for part in path.parts)

    for spec in LANGUAGE_SPECS:
        cdx_type = spec["type"]
        # 1. Check root markers (fast path)
        for marker in spec["root"]:
            if (p / marker).exists():
                found[cdx_type] = {
                    "type": cdx_type,
                    "name": spec["name"],
                    "icon": spec["icon"],
                    "marker": marker,
                }
                break

        if cdx_type in found:
            continue

        # 2. Glob search (recursive, limited depth)
        for pattern in spec["glob"]:
            for hit in p.glob(pattern):
                if not _is_skipped(hit.relative_to(p)):
                    found[cdx_type] = {
                        "type": cdx_type,
                        "name": spec["name"],
                        "icon": spec["icon"],
                        "marker": str(hit.relative_to(p)),
                    }
                    break
            if cdx_type in found:
                break

    # gradle is more specific than java — drop java if both detected
    if "gradle" in found and "java" in found:
        del found["java"]

    # Fallback: look for raw .c/.cpp files
    if not found:
        for ext in ("*.c", "*.cpp", "*.cc", "*.cxx"):
            hits = [h for h in p.rglob(ext) if not _is_skipped(h.relative_to(p))]
            if hits:
                found["c"] = {"type": "c", "name": "C/C++", "icon": "⚙️", "marker": ext}
                break

    if not found:
        found["c"] = {"type": "c", "name": "C/C++", "icon": "⚙️", "marker": "(auto)"}

    return list(found.values())


@app.get("/api/detect")
async def detect_languages(path: str):
    p = Path(path)
    if not p.is_dir():
        raise HTTPException(404, "Директория не найдена")
    langs = _detect_languages(path)
    return {"path": path, "languages": langs}


# ═══════════════════════════════════════════════════════════════════════════
# Pipeline helpers
# ═══════════════════════════════════════════════════════════════════════════

def _log(job_id: str, line: str):
    """Append to in-memory log cache; flush to DB every 50 lines."""
    if job_id not in _LOG_CACHE:
        _LOG_CACHE[job_id] = []
    _LOG_CACHE[job_id].append(line)
    # Flush to DB every 50 lines or immediately if short line
    if len(_LOG_CACHE[job_id]) % 50 == 0:
        _flush_logs(job_id)


def _flush_logs(job_id: str):
    """Write accumulated logs to SQLite."""
    if job_id in _LOG_CACHE:
        logs = _LOG_CACHE[job_id]
        job_store.update_job(job_id, logs=logs)


def _run(job_id: str, cmd: list, cwd: str | None = None, env: dict | None = None) -> int:
    _log(job_id, f"\n$ {' '.join(str(c) for c in cmd)}")
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, cwd=cwd, env=env or CHECKER_ENV,
    )
    for line in proc.stdout:
        _log(job_id, line.rstrip())
    proc.wait()
    return proc.returncode


def _filter_noise(job_id: str, src: Path, dst: Path):
    """Remove system deb/rpm/apk packages via jq."""
    jq_expr = (
        r'def sys: (.purl? // "") | test("^pkg:(deb|rpm|apk)/") or'
        r' ((.name? // "") | test("^(linux-|libc6$|libgcc|libstdc\\+\\+|gcc-[0-9]'
        r'|binutils|coreutils|base-files|base-passwd|bash$|debianutils|dpkg'
        r'|e2fsprogs|findutils|gzip$|hostname$|init-system-helpers|login$|mount$'
        r'|procps|sed$|sensible-utils|sysvinit-utils|tar$|tzdata|util-linux|zlib1g$)"));'
        r'([.components[]? | select(sys)] | length) as $rm |'
        r'.components = [.components[]? | select(sys | not)] |'
        r'.metadata.properties = ((.metadata.properties // []) +'
        r' [{"name":"sbom:noise_filtered","value":($rm|tostring)}])'
    )
    res = subprocess.run(["jq", jq_expr, str(src)], capture_output=True, text=True)
    if res.returncode == 0 and res.stdout.strip():
        dst.write_text(res.stdout)
        try:
            removed = json.loads(res.stdout).get("metadata", {}).get("properties", [])
            n = next((p["value"] for p in removed if p.get("name") == "sbom:noise_filtered"), "?")
            _log(job_id, f"  ✓ Шум убран: {n} системных пакетов удалено")
        except Exception:
            _log(job_id, "  ✓ Фильтрация выполнена")
    else:
        _log(job_id, f"  ⚠ jq: {res.stderr[:200] or 'ошибка'} — копирую без фильтра")
        shutil.copy(src, dst)


def _merge_sboms(job_id: str, sbom_files: list[Path], out: Path) -> bool:
    """Merge multiple CycloneDX JSON SBOMs into one via jq dedup."""
    if len(sbom_files) == 1:
        shutil.copy(sbom_files[0], out)
        return True

    # Try cyclonedx-cli merge first
    if shutil.which("cyclonedx"):
        args = []
        for f in sbom_files:
            args += ["--input-file", str(f)]
        rc = _run(job_id, [
            "cyclonedx", "merge",
            *args,
            "--output-file", str(out),
            "--output-format", "json",
        ], env={**os.environ})
        if rc == 0 and out.exists() and out.stat().st_size > 10:
            _log(job_id, f"  ✓ Слияние через cyclonedx-cli: {len(sbom_files)} файлов")
            return True

    # Fallback: jq merge with deduplication by purl
    jq_expr = (
        r'.[0] as $base | reduce .[1:][] as $other ($base; '
        r'.components += ($other.components // [])) | '
        r'.components = ([.components[] | {key: (.purl // (.name + "@" + (.version // ""))), value: .}] '
        r'| group_by(.key) | map(.[0].value))'
    )
    res = subprocess.run(
        ["jq", "-s", jq_expr] + [str(f) for f in sbom_files],
        capture_output=True, text=True,
    )
    if res.returncode == 0 and res.stdout.strip():
        out.write_text(res.stdout)
        _log(job_id, f"  ✓ Слияние через jq: {len(sbom_files)} файлов")
        return True

    _log(job_id, "  ⚠ Слияние не удалось, использую первый файл")
    shutil.copy(sbom_files[0], out)
    return False


def _quality_check(job_id: str, sbom_path: Path) -> dict:
    """Quality check per CISA 2025 + NTIA minimum elements. Returns score 0-100."""
    _log(job_id, "\n" + "═" * 60)
    _log(job_id, "▶ ШАГ: Проверка качества SBOM (CISA 2025 + NTIA)")
    _log(job_id, "═" * 60)

    try:
        with open(sbom_path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        _log(job_id, f"  ✗ Не удалось прочитать SBOM: {e}")
        return {}

    checks = []
    comps = data.get("components", [])
    meta  = data.get("metadata", {})
    total = len(comps)

    def chk(name: str, passed: bool, detail: str = "", critical: bool = False):
        checks.append({"name": name, "passed": passed, "detail": detail, "critical": critical})
        mark = "✓" if passed else ("✗" if critical else "⚠")
        _log(job_id, f"  {mark} {name}" + (f": {detail}" if detail else ""))

    chk("bomFormat = CycloneDX",     data.get("bomFormat") == "CycloneDX", critical=True)
    chk("specVersion присутствует",  bool(data.get("specVersion")), critical=True)
    chk("serialNumber (UUID)",        bool(data.get("serialNumber")), "urn:uuid:…")
    chk("version (целое число)",      isinstance(data.get("version"), int))
    chk("metadata.timestamp",         bool(meta.get("timestamp")),
        detail=meta.get("timestamp", "ОТСУТСТВУЕТ"), critical=True)

    tools = meta.get("tools", {})
    has_tools = bool(tools.get("components") or tools.get("services") or isinstance(tools, list))
    chk("metadata.tools (CISA 2025)", has_tools, "наименование инструмента генерации")

    mfr = meta.get("manufacture") or meta.get("manufacturer") or meta.get("supplier")
    chk("metadata.manufacture/supplier (CISA 2025)", bool(mfr))

    mc = meta.get("component", {})
    chk("metadata.component.name",    bool(mc.get("name")), critical=True)
    chk("metadata.component.version", bool(mc.get("version")))

    if total == 0:
        _log(job_id, "  ⚠ В SBOM нет компонентов!")
        chk("Есть компоненты", False, "список components пуст", critical=True)
        score = 10 if all(c["passed"] for c in checks if c["critical"]) else 0
        return {"score": score, "checks": checks, "total": 0}

    def pct(lst): return f"{sum(lst)}/{total} ({100*sum(lst)//total}%)"

    has_purl = [bool(c.get("purl"))    for c in comps]
    has_ver  = [bool(c.get("version")) for c in comps]
    has_lic  = [bool(c.get("licenses")) for c in comps]
    has_hash = [bool(c.get("hashes"))  for c in comps]
    has_name = [bool(c.get("name"))    for c in comps]
    has_type = [bool(c.get("type"))    for c in comps]
    has_refs = [bool(c.get("externalReferences")) for c in comps]

    chk("Все компоненты имеют name",    all(has_name),    pct(has_name),    critical=True)
    chk("PURL (NTIA / CISA 2025)",      all(has_purl),    pct(has_purl),    critical=True)
    chk("Version (NTIA / CISA 2025)",   all(has_ver),     pct(has_ver),     critical=True)
    chk("Hash SHA-256 (CISA 2025 new)", all(has_hash),    pct(has_hash))
    chk("Licenses (CISA 2025 new)",     all(has_lic),     pct(has_lic))
    chk("type (library/framework/…)",   all(has_type),    pct(has_type))
    chk("externalReferences (VCS)",     sum(has_refs) > 0, pct(has_refs))

    bad_purl = [c["purl"] for c in comps if c.get("purl") and not c["purl"].startswith("pkg:")]
    chk("PURL-формат (pkg:…)",          len(bad_purl) == 0,
        f"неверных: {len(bad_purl)}" if bad_purl else "")

    chk("dependencies (граф зависимостей)", bool(data.get("dependencies")))

    # CISA 2025: Generation Context — formulation section (cdxgen --include-formulation)
    has_formulation = bool(data.get("formulation"))
    chk("formulation (CISA 2025 Generation Context)", has_formulation,
        "cdxgen --include-formulation или --profile appsec")

    weights = {
        "bomFormat = CycloneDX": 10,
        "specVersion присутствует": 5,
        "metadata.timestamp": 8,
        "metadata.tools (CISA 2025)": 7,
        "Все компоненты имеют name": 10,
        "PURL (NTIA / CISA 2025)": 15,
        "Version (NTIA / CISA 2025)": 10,
        "Hash SHA-256 (CISA 2025 new)": 8,
        "Licenses (CISA 2025 new)": 8,
        "PURL-формат (pkg:…)": 5,
        "dependencies (граф зависимостей)": 4,
        "serialNumber (UUID)": 3,
        "metadata.component.name": 5,
        "type (library/framework/…)": 3,
        "formulation (CISA 2025 Generation Context)": 5,
    }
    earned = sum(w for c in checks if c["passed"] for name, w in weights.items() if name == c["name"])
    max_w  = sum(weights.values())
    score  = round(100 * earned / max_w)
    _log(job_id, f"\n  📊 Quality Score: {score}/100")
    return {"score": score, "checks": checks, "total": total}


# ═══════════════════════════════════════════════════════════════════════════
# Multi-Language SBOM Generation
# ═══════════════════════════════════════════════════════════════════════════

def _run_cdxgen_multi(job_id: str, project_path: str, langs: list[dict],
                      out_dir: Path, spec_ver: str, proj_name: str, proj_ver: str,
                      filters: list, extra: list) -> Optional[Path]:
    """
    Run cdxgen ONCE with all detected language types as multiple --type flags.
    Adds --deep for C/C++ projects, --evidence for richer metadata.
    Returns output path or None.
    """
    types = [l["type"] for l in langs]
    has_c = "c" in types

    type_args = []
    for t in types:
        type_args += ["--type", t]

    raw_out = out_dir / "sbom-cdxgen-raw.json"

    profile = "appsec"  # appsec profile auto-enables --deep + evidence
    extra_flags = list(extra)
    extra_flags += ["--include-formulation"]  # CISA 2025: Generation Context
    extra_flags += ["--recurse"]              # recurse into subdirs
    # --deep is already enabled by appsec profile for C/C++
    if has_c and "appsec" not in profile:
        extra_flags += ["--deep"]

    lang_names = ", ".join(f"{l.get('icon','')} {l['name']}" for l in langs)
    _log(job_id, f"\n  ▸ cdxgen --type {' --type '.join(types)} --profile {profile} --include-formulation")
    _log(job_id, f"    Языки: {lang_names}")

    rc = _run(job_id, [
        "cdxgen",
        *type_args,
        "--spec-version",     spec_ver,
        "--output",           str(raw_out),
        "--project-name",     proj_name,
        "--project-version",  proj_ver,
        "--profile",          profile,
        *filters, *extra_flags,
        project_path,
    ], env={**os.environ})

    if rc != 0:
        _log(job_id, f"  ⚠ cdxgen завершился с кодом {rc}")

    if raw_out.exists() and raw_out.stat().st_size > 50:
        try:
            data = json.loads(raw_out.read_text())
            cnt = len(data.get("components", []))
            if cnt > 0 or data.get("metadata", {}).get("component"):
                # Show breakdown by ecosystem
                ecosystems: dict[str, int] = {}
                for c in data.get("components", []):
                    purl = c.get("purl", "")
                    if purl and ":" in purl:
                        eco = purl.split(":")[1].split("/")[0]
                        ecosystems[eco] = ecosystems.get(eco, 0) + 1
                eco_str = ", ".join(f"{k}:{v}" for k, v in sorted(ecosystems.items()))
                _log(job_id, f"  ✓ cdxgen: {cnt} компонентов [{eco_str}]")
                return raw_out
        except Exception:
            pass
        _log(job_id, "  ⚠ cdxgen SBOM пуст или невалиден")

    return None


def _run_cdxgen_auto(job_id: str, project_path: str, out_dir: Path,
                     spec_ver: str, proj_name: str, proj_ver: str) -> Optional[Path]:
    """
    Fallback: run cdxgen without --type (full auto-detection).
    Used when per-type scan yields nothing.
    """
    raw_out = out_dir / "sbom-auto-raw.json"
    _log(job_id, "\n  ▸ cdxgen [auto-detect без --type]")
    rc = _run(job_id, [
        "cdxgen",
        "--spec-version",    spec_ver,
        "--output",          str(raw_out),
        "--project-name",    proj_name,
        "--project-version", proj_ver,
        "--evidence",
        "--recurse",
        project_path,
    ], env={**os.environ})

    if rc != 0:
        _log(job_id, f"  ⚠ cdxgen auto завершился с кодом {rc}")

    if raw_out.exists() and raw_out.stat().st_size > 50:
        try:
            data = json.loads(raw_out.read_text())
            cnt = len(data.get("components", []))
            if cnt > 0:
                _log(job_id, f"  ✓ cdxgen auto: {cnt} компонентов")
                return raw_out
        except Exception:
            pass

    return None


def _run_syft(job_id: str, project_path: str, out_dir: Path, spec_ver: str,
              has_conan: bool) -> Optional[Path]:
    """Run syft for binary/conan analysis. Returns output path or None."""
    if not shutil.which("syft"):
        return None

    catalogers = "conan-cataloger,binary-cataloger" if has_conan else "binary-cataloger"
    raw_out = out_dir / "sbom-syft-raw.json"

    _log(job_id, f"\n  ▸ syft [binary+conan] catalogers={catalogers}")
    _run(job_id, [
        "syft", f"dir:{project_path}",
        "--output",                    f"cyclonedx-json@{spec_ver}={raw_out}",
        "--override-default-catalogers", catalogers,
        "--exclude", "/usr/share/**",
        "--exclude", "/var/**",
        "--exclude", "/etc/**",
        "--exclude", "**/.git/**",
        "--exclude", "**/node_modules/**",
    ], env={**os.environ})

    if raw_out.exists() and raw_out.stat().st_size > 50:
        try:
            data = json.loads(raw_out.read_text())
            cnt = len(data.get("components", []))
            if cnt > 0:
                _log(job_id, f"  ✓ syft: {cnt} компонентов")
                return raw_out
        except Exception:
            pass

    return None


# ═══════════════════════════════════════════════════════════════════════════
# Main Pipeline
# ═══════════════════════════════════════════════════════════════════════════
def _pipeline(job_id: str, params: dict):
    _LOG_CACHE[job_id] = []
    job_store.update_job(job_id, status="running")
    out_dir = Path(job_store.get_job(job_id)["output_dir"])
    mode = params.get("mode", "both")

    try:
        generated_sbom: Optional[Path] = None

        # ── STEP 1: Generation ──────────────────────────────────────────────
        if mode in ("generate", "both"):
            _log(job_id, "═" * 60)
            _log(job_id, "▶ ШАГ 1: Генерация SBOM (полиглот-режим)")
            _log(job_id, "═" * 60)

            project_path = params.get("project_path", "").strip()
            if not project_path or not Path(project_path).exists():
                _log(job_id, f"✗ Путь не найден: {project_path!r}")
                _finalize_job(job_id, "error")
                return

            p = Path(project_path)
            spec_ver  = str(params.get("spec_version", "1.6"))
            proj_name = (params.get("project_name") or p.name).strip() or "project"
            proj_ver  = (params.get("project_version") or "0.0.0").strip()
            scanner   = params.get("scanner", "auto")

            filters = []
            if params.get("filter_deb", True):  filters += ["--filter", "pkg:deb"]
            if params.get("filter_rpm", True):  filters += ["--filter", "pkg:rpm"]
            if params.get("filter_apk", True):  filters += ["--filter", "pkg:apk"]
            extra = ["--required-only"] if params.get("required_only") else []

            raw_sboms: list[Path] = []

            # Auto-detect languages unless user provided explicit override
            override_types = params.get("project_types")  # list[str] from UI or None
            if override_types:
                langs = [{"type": t, "name": t, "icon": ""} for t in override_types]
                _log(job_id, f"  Языки (вручную): {', '.join(override_types)}")
            else:
                langs = _detect_languages(project_path)

            job_store.update_job(job_id, detected_languages=langs)
            lang_names = ", ".join(f"{l.get('icon','')} {l['name']}" for l in langs)
            _log(job_id, f"  Обнаружены экосистемы: {lang_names}")

            # cdxgen: one invocation with all detected types
            if scanner in ("cdxgen", "auto", "both") and langs:
                result = _run_cdxgen_multi(
                    job_id, project_path, langs,
                    out_dir, spec_ver, proj_name, proj_ver, filters, extra,
                )
                if result:
                    raw_sboms.append(result)
                else:
                    # Fallback: auto-detect mode (no --type)
                    _log(job_id, "  ⚠ Multi-type scan не дал результатов, пробую auto-detect...")
                    result = _run_cdxgen_auto(
                        job_id, project_path, out_dir, spec_ver, proj_name, proj_ver,
                    )
                    if result:
                        raw_sboms.append(result)

            # syft for additional binary analysis (C/C++ projects)
            has_conan = (p / "conanfile.py").exists() or (p / "conanfile.txt").exists()
            if scanner in ("syft", "auto", "both"):
                result = _run_syft(job_id, project_path, out_dir, spec_ver, has_conan)
                if result:
                    raw_sboms.append(result)

            if not raw_sboms:
                _log(job_id, "✗ SBOM не создан — ни один сканер не вернул результат")
            else:
                # Filter noise from each SBOM
                _log(job_id, "\n▶ Фильтрация системных пакетов...")
                filtered: list[Path] = []
                for raw in raw_sboms:
                    dst = raw.parent / raw.name.replace("-raw.json", "-filtered.json")
                    _filter_noise(job_id, raw, dst)
                    if dst.exists() and dst.stat().st_size > 10:
                        filtered.append(dst)

                if not filtered:
                    filtered = raw_sboms

                # Merge if multiple
                if len(filtered) > 1:
                    _log(job_id, f"\n▶ Слияние {len(filtered)} SBOM-файлов...")
                    merged = out_dir / "sbom-merged.json"
                    _merge_sboms(job_id, filtered, merged)
                    generated_sbom = merged
                else:
                    generated_sbom = filtered[0]

        # ── STEP 2: Determine input SBOM ────────────────────────────────────
        sbom_in: Optional[Path] = None
        if mode == "validate":
            inp = params.get("input_sbom", "").strip()
            sbom_in = Path(inp) if inp and Path(inp).exists() else None
            if not sbom_in:
                _log(job_id, "✗ Файл для валидации не найден")
                _finalize_job(job_id, "error")
                return
        else:
            sbom_in = generated_sbom

        if not sbom_in:
            _log(job_id, "✗ Нет SBOM-файла для обработки")
            _finalize_job(job_id, "error")
            return

        # ── STEP 3: sbom-updater enrichment ─────────────────────────────────
        enriched: Optional[Path] = None
        if params.get("run_updater", True):
            _log(job_id, "\n" + "═" * 60)
            _log(job_id, "▶ ШАГ 2: Обогащение (sbom-updater ИСПРАН)")
            _log(job_id, "═" * 60)

            enriched_out = out_dir / "sbom-enriched.json"
            cmd = [PYTHON, str(UPDATER_PY)]

            if params.get("updater_fix_all"):
                cmd.append("--fix-all")
            else:
                if params.get("updater_props"): cmd.append("--props")
                if params.get("updater_ref"):   cmd.append("--ref")

            if params.get("app_name"):      cmd += ["--app-name",      params["app_name"]]
            if params.get("app_version"):   cmd += ["--app-version",   params["app_version"]]
            if params.get("manufacturer"):  cmd += ["--manufacturer",  params["manufacturer"]]
            old = (params.get("old_sbom") or "").strip()
            if old and Path(old).exists():  cmd += ["--update", old]
            if params.get("verbose"):       cmd.append("-v")

            cmd += [str(sbom_in), str(enriched_out)]
            _run(job_id, cmd, cwd=str(CHECKER_DIR))
            if enriched_out.exists() and enriched_out.stat().st_size > 10:
                enriched = enriched_out
                _log(job_id, f"✓ Обогащение выполнено → {enriched_out.name}")
            else:
                _log(job_id, "⚠  sbom-updater не создал файл, использую исходный")
                enriched = sbom_in

        final_sbom = enriched or sbom_in

        # ── STEP 4: sbom-checker validation ─────────────────────────────────
        checker_passed = None
        if params.get("run_checker", True):
            _log(job_id, "\n" + "═" * 60)
            _log(job_id, "▶ ШАГ 3: Валидация схемы (sbom-checker ИСПРАН)")
            _log(job_id, "═" * 60)

            checker_format = params.get("checker_format", "oss")
            cmd = [
                PYTHON, str(CHECKER_PY),
                "--purl-validation", "yes" if params.get("purl_validation", True) else "no",
                "--format",  checker_format,
                "--errors",  str(params.get("max_errors", 0)),
            ]
            if params.get("check_vcs"):         cmd.append("--check-vcs-leaf-only")
            if params.get("check_source_dist"): cmd.append("--check-source-distribution")
            if params.get("verbose"):            cmd.append("-v")
            cmd.append(str(final_sbom))

            rc = _run(job_id, cmd, cwd=str(CHECKER_DIR))
            checker_passed = (rc == 0)
            _log(job_id, ("✓ sbom-checker: PASSED" if checker_passed
                          else f"⚠  sbom-checker: проблемы найдены (код {rc})"))

        # ── STEP 5: CISA 2025 quality check ─────────────────────────────────
        quality = _quality_check(job_id, final_sbom)

        # ── STEP 6: Export CSV + ODT ─────────────────────────────────────────
        _log(job_id, "\n" + "═" * 60)
        _log(job_id, "▶ ШАГ 4: Экспорт (CSV, ODT)")
        _log(job_id, "═" * 60)

        csv_out = out_dir / "sbom.csv"
        _run(job_id, [PYTHON, str(TO_CSV_PY), str(final_sbom), str(csv_out)],
             cwd=str(CHECKER_DIR))
        if csv_out.exists(): _log(job_id, f"✓ CSV: {csv_out.name}")

        checker_format = params.get("checker_format", "oss")
        odt_format = checker_format.replace("2025", "") or "oss"
        odt_out = out_dir / "sbom.odt"
        _run(job_id, [PYTHON, str(TO_ODT_PY), "--format", odt_format,
                      str(final_sbom), str(odt_out)], cwd=str(CHECKER_DIR))
        if odt_out.exists(): _log(job_id, f"✓ ODT: {odt_out.name}")

        # ── Collect stats ─────────────────────────────────────────────────────
        stats = _collect_stats(final_sbom)
        output_files = [f.name for f in out_dir.iterdir() if f.is_file()]

        _log(job_id, "\n" + "═" * 60)
        _log(job_id, "✓ Pipeline завершён успешно")
        _log(job_id, "═" * 60)

        job_store.update_job(job_id,
            stats=stats,
            quality=quality,
            output_files=output_files,
            checker_passed=1 if checker_passed else (0 if checker_passed is False else None),
            final_sbom=final_sbom.name,
        )
        _finalize_job(job_id, "done")

    except Exception as exc:
        _log(job_id, f"\n✗ КРИТИЧЕСКАЯ ОШИБКА: {exc}")
        import traceback
        _log(job_id, traceback.format_exc())
        _finalize_job(job_id, "error")


def _finalize_job(job_id: str, status: str):
    _flush_logs(job_id)
    job_store.update_job(job_id, status=status)


def _collect_stats(sbom_path: Path) -> dict:
    try:
        with open(sbom_path, encoding="utf-8") as f:
            data = json.load(f)
        comps = data.get("components", [])

        ecosystems: dict[str, int] = {}
        for c in comps:
            purl = c.get("purl", "")
            if purl and ":" in purl:
                eco = purl.split(":")[1].split("/")[0]
                ecosystems[eco] = ecosystems.get(eco, 0) + 1

        return {
            "total":        len(comps),
            "with_purl":    sum(1 for c in comps if c.get("purl")),
            "with_version": sum(1 for c in comps if c.get("version")),
            "with_license": sum(1 for c in comps if c.get("licenses")),
            "with_hash":    sum(1 for c in comps if c.get("hashes")),
            "with_refs":    sum(1 for c in comps if c.get("externalReferences")),
            "spec_version": data.get("specVersion", "?"),
            "ecosystems":   ecosystems,
            "components": [
                {
                    "name":      c.get("name", ""),
                    "version":   c.get("version", ""),
                    "purl":      c.get("purl", ""),
                    "type":      c.get("type", ""),
                    "licenses":  ", ".join(
                        ll.get("license", {}).get("id") or ll.get("license", {}).get("name", "")
                        for ll in (c.get("licenses") or []) if isinstance(ll, dict)
                    ),
                }
                for c in comps[:500]
            ],
        }
    except Exception:
        return {}


# ═══════════════════════════════════════════════════════════════════════════
# API: run job
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/api/run")
async def run_job(background_tasks: BackgroundTasks, params: dict = Body(...)):
    job_id = uuid.uuid4().hex[:12]
    out_dir = JOBS_DIR / job_id
    out_dir.mkdir()

    job_store.create_job(job_id, str(out_dir), params)
    background_tasks.add_task(_pipeline, job_id, params)
    return {"job_id": job_id}


# ═══════════════════════════════════════════════════════════════════════════
# API: SSE log stream
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/stream/{job_id}")
async def stream_logs(job_id: str):
    if not job_store.get_job(job_id):
        raise HTTPException(404)

    async def gen():
        sent = 0
        while True:
            # Prefer in-memory cache (faster for running jobs)
            if job_id in _LOG_CACHE:
                logs = _LOG_CACHE[job_id]
            else:
                logs = job_store.get_logs(job_id)

            while sent < len(logs):
                yield f"data: {json.dumps(logs[sent])}\n\n"
                sent += 1

            j = job_store.get_job(job_id) or {}
            if j.get("status") in ("done", "error") and sent >= len(logs):
                yield "data: __DONE__\n\n"
                break
            await asyncio.sleep(0.15)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ═══════════════════════════════════════════════════════════════════════════
# API: job status
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/job/{job_id}")
async def get_job(job_id: str):
    j = job_store.get_job(job_id)
    if not j:
        raise HTTPException(404)
    return {
        "id":                  j["id"],
        "status":              j["status"],
        "stats":               j.get("stats") or {},
        "quality":             j.get("quality") or {},
        "output_files":        j.get("output_files") or [],
        "checker_passed":      bool(j["checker_passed"]) if j["checker_passed"] is not None else None,
        "final_sbom":          j["final_sbom"],
        "detected_languages":  j.get("detected_languages") or [],
    }


# ═══════════════════════════════════════════════════════════════════════════
# API: download file
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/download/{job_id}/{filename}")
async def download_file(job_id: str, filename: str):
    j = job_store.get_job(job_id)
    if not j:
        raise HTTPException(404)
    path = (Path(j["output_dir"]) / filename).resolve()
    if not str(path).startswith(str(JOBS_DIR)):
        raise HTTPException(403)
    if not path.is_file():
        raise HTTPException(404, "Файл не найден")
    return FileResponse(path, filename=filename)


# ═══════════════════════════════════════════════════════════════════════════
# API: job history
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/jobs")
async def list_jobs():
    jobs = job_store.list_jobs(200)
    return [
        {
            "id": j["id"],
            "status": j["status"],
            "created_at": j["created_at"],
            "project": (j.get("params") or {}).get("project_name")
                       or (j.get("params") or {}).get("app_name", "?"),
            "quality_score": (j.get("quality") or {}).get("score"),
            "detected_languages": j.get("detected_languages") or [],
        }
        for j in jobs
    ]


# ═══════════════════════════════════════════════════════════════════════════
# BDU API
# ═══════════════════════════════════════════════════════════════════════════

def _bdu_import_task(task_id: str, zip_path: str):
    BDU_JOBS[task_id]["status"] = "running"
    BDU_JOBS[task_id]["logs"] = []

    def progress(n):
        BDU_JOBS[task_id]["logs"].append(f"  Загружено: {n:,} записей...")
        BDU_JOBS[task_id]["progress"] = n

    try:
        BDU_JOBS[task_id]["logs"].append(f"Начало импорта: {zip_path}")
        count = build_db(zip_path, db_path=BDU_DB, progress_cb=progress)
        BDU_JOBS[task_id]["status"] = "done"
        BDU_JOBS[task_id]["count"] = count
        BDU_JOBS[task_id]["logs"].append(f"✓ Импорт завершён: {count:,} уязвимостей")
    except Exception as e:
        BDU_JOBS[task_id]["status"] = "error"
        BDU_JOBS[task_id]["logs"].append(f"✗ Ошибка: {e}")
        import traceback
        BDU_JOBS[task_id]["logs"].append(traceback.format_exc())


@app.get("/api/bdu/status")
async def bdu_status():
    if not BDU_AVAILABLE:
        return {"available": False, "error": "bdu_parser модуль недоступен"}
    stats = get_stats(BDU_DB)
    meta  = get_meta(BDU_DB)
    return {"available": True, "db_exists": db_exists(BDU_DB),
            "stats": stats, "meta": meta}


@app.post("/api/bdu/import")
async def bdu_import(background_tasks: BackgroundTasks, params: dict = Body(...)):
    if not BDU_AVAILABLE:
        raise HTTPException(503, "bdu_parser недоступен")
    zip_path = params.get("zip_path", "/root/sbomsauto/vulxml.zip")
    if not Path(zip_path).exists():
        raise HTTPException(404, f"Файл не найден: {zip_path}")

    task_id = uuid.uuid4().hex[:10]
    BDU_JOBS[task_id] = {
        "id": task_id, "status": "pending",
        "logs": [], "progress": 0, "count": 0,
        "created_at": time.time(),
    }
    background_tasks.add_task(_bdu_import_task, task_id, zip_path)
    return {"task_id": task_id}


@app.get("/api/bdu/import/{task_id}/stream")
async def bdu_import_stream(task_id: str):
    if task_id not in BDU_JOBS:
        raise HTTPException(404)

    async def gen():
        sent = 0
        while True:
            j = BDU_JOBS.get(task_id, {})
            logs = j.get("logs", [])
            while sent < len(logs):
                yield f"data: {json.dumps(logs[sent])}\n\n"
                sent += 1
            if j.get("status") in ("done", "error") and sent >= len(logs):
                yield f"data: __DONE__{json.dumps({'count': j.get('count', 0), 'status': j.get('status')})}\n\n"
                break
            await asyncio.sleep(0.5)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/api/bdu/scan")
async def bdu_scan(background_tasks: BackgroundTasks, params: dict = Body(...)):
    if not BDU_AVAILABLE:
        raise HTTPException(503, "bdu_matcher недоступен")
    if not db_exists(BDU_DB):
        raise HTTPException(409, "База BDU не загружена. Сначала выполните импорт.")

    sbom_path: Optional[Path] = None
    job_id = params.get("job_id")
    if job_id:
        j = job_store.get_job(job_id)
        if j and j.get("final_sbom"):
            sbom_path = Path(j["output_dir"]) / j["final_sbom"]
    if not sbom_path:
        direct = params.get("sbom_path", "")
        if direct:
            sbom_path = Path(direct)
    if not sbom_path or not sbom_path.exists():
        raise HTTPException(404, "SBOM файл не найден")

    task_id = uuid.uuid4().hex[:10]
    BDU_JOBS[task_id] = {
        "id": task_id, "status": "running",
        "logs": [f"Сканирование: {sbom_path.name}"],
        "result": None, "created_at": time.time(),
    }

    def _do_scan():
        try:
            result = scan_sbom(sbom_path, db_path=BDU_DB)


            BDU_JOBS[task_id]["result"] = result
            BDU_JOBS[task_id]["status"] = "done"
            s = result["stats"]
            BDU_JOBS[task_id]["logs"].append(
                f"✓ Готово: {s['affected_components']} компонентов с уязвимостями, "
                f"{s['total_vulns']} всего (critical={s.get('critical',0)}, high={s.get('high',0)})"
            )

            # ── Auto-generate VEX SBOM ────────────────────────────────────
            if IMPORTERS_OK:
                try:
                    vex_out = sbom_path.parent / (sbom_path.stem + "-vex.json")
                    embed_vex_into_sbom(sbom_path, result, vex_out)
                    BDU_JOBS[task_id]["vex_file"] = vex_out.name
                    BDU_JOBS[task_id]["logs"].append(f"  ✓ VEX SBOM сгенерирован: {vex_out.name}")
                    # Update job output_files if we know the job_id
                    src_job = params.get("job_id")
                    if src_job:
                        jj = job_store.get_job(src_job)
                        if jj:
                            files = list(set((jj.get("output_files") or []) + [vex_out.name]))
                            job_store.update_job(src_job, output_files=files)
                except Exception as ve:
                    BDU_JOBS[task_id]["logs"].append(f"  ⚠ VEX: {ve}")

        except Exception as e:
            BDU_JOBS[task_id]["status"] = "error"
            BDU_JOBS[task_id]["logs"].append(f"✗ Ошибка: {e}")

    background_tasks.add_task(_do_scan)
    return {"task_id": task_id}


@app.get("/api/bdu/scan/{task_id}")
async def bdu_scan_result(task_id: str):
    if task_id not in BDU_JOBS:
        raise HTTPException(404)
    j = BDU_JOBS[task_id]
    return {"status": j["status"], "logs": j.get("logs", []), "result": j.get("result")}


@app.get("/api/bdu/search")
async def bdu_search(q: str, limit: int = 10):
    if not BDU_AVAILABLE or not db_exists(BDU_DB):
        raise HTTPException(409, "База BDU не загружена")
    results = match_component(name=q, limit=limit, db_path=BDU_DB)
    return {"results": results}


# ═══════════════════════════════════════════════════════════════════════════
# API: BDU scan with VEX + XLSX export
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/bdu/scan/{task_id}/vex")
async def bdu_generate_vex(task_id: str, params: dict = Body(default={})):
    """Embed BDU scan results as VEX section into SBOM JSON."""
    if task_id not in BDU_JOBS:
        raise HTTPException(404, "Задача не найдена")
    j = BDU_JOBS[task_id]
    if j.get("status") != "done" or not j.get("result"):
        raise HTTPException(409, "Сканирование ещё не завершено")
    if not IMPORTERS_OK:
        raise HTTPException(503, "vex_generator недоступен")

    # Find SBOM from job
    job_id = params.get("job_id")
    sbom_path: Optional[Path] = None
    if job_id:
        jj = job_store.get_job(job_id)
        if jj and jj.get("final_sbom"):
            sbom_path = Path(jj["output_dir"]) / jj["final_sbom"]
    if not sbom_path or not sbom_path.exists():
        direct = params.get("sbom_path", "")
        if direct:
            sbom_path = Path(direct)
    if not sbom_path or not sbom_path.exists():
        raise HTTPException(404, "SBOM файл не найден")

    out_path = sbom_path.parent / (sbom_path.stem + "-vex.json")
    embed_vex_into_sbom(sbom_path, j["result"], out_path)

    # Update job output files
    if job_id:
        jj = job_store.get_job(job_id)
        if jj:
            files = list(set((jj.get("output_files") or []) + [out_path.name]))
            job_store.update_job(job_id, output_files=files)

    return {"vex_file": out_path.name, "vulnerabilities_count": len(j["result"].get("components", []))}


@app.post("/api/bdu/scan/{task_id}/xlsx")
async def bdu_export_xlsx(task_id: str, params: dict = Body(default={})):
    """Export BDU scan results + SBOM stats to XLSX."""
    if task_id not in BDU_JOBS:
        raise HTTPException(404, "Задача не найдена")
    j = BDU_JOBS[task_id]
    if j.get("status") != "done" or not j.get("result"):
        raise HTTPException(409, "Сканирование ещё не завершено")
    if not IMPORTERS_OK:
        raise HTTPException(503, "xlsx_exporter недоступен")

    job_id = params.get("job_id")
    sbom_stats = {}
    out_dir: Optional[Path] = None
    if job_id:
        jj = job_store.get_job(job_id)
        if jj:
            sbom_stats = jj.get("stats") or {}
            out_dir = Path(jj["output_dir"])
    if not out_dir:
        out_dir = JOBS_DIR / "exports"
        out_dir.mkdir(exist_ok=True)

    xlsx_path = out_dir / "bdu-report.xlsx"
    ok = export_bdu_scan(j["result"], sbom_stats, xlsx_path)
    if not ok:
        raise HTTPException(500, "openpyxl недоступен, установите: pip install openpyxl")

    if job_id:
        jj = job_store.get_job(job_id)
        if jj:
            files = list(set((jj.get("output_files") or []) + [xlsx_path.name]))
            job_store.update_job(job_id, output_files=files)

    return FileResponse(xlsx_path, filename="bdu-report.xlsx",
                        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


# ═══════════════════════════════════════════════════════════════════════════
# API: Import external scanner results (Grype, Trivy, SARIF, OSV)
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/import")
async def import_scanner_results(file: UploadFile = File(...)):
    """
    Auto-detect and import vulnerability scanner results.
    Supports: Grype JSON, Trivy JSON, OSV-Scanner JSON, SARIF 2.1.0, Generic JSON.
    Returns normalized findings list.
    """
    if not IMPORTERS_OK:
        raise HTTPException(503, "vuln_importer недоступен")

    data = await file.read()
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(413, "Файл слишком большой (макс. 50 МБ)")

    try:
        fmt, findings = import_vuln_file(data)
    except ValueError as e:
        raise HTTPException(400, str(e))

    # Deduplicate by fingerprint
    seen: set[str] = set()
    unique = []
    for f in findings:
        fp = f.get("fingerprint", "")
        if fp not in seen:
            seen.add(fp)
            unique.append(f)

    # Stats
    stats: dict[str, int] = {}
    for f in unique:
        sev = f.get("severity", "unknown")
        stats[sev] = stats.get(sev, 0) + 1

    return {
        "format":      fmt,
        "imported":    len(unique),
        "duplicates":  len(findings) - len(unique),
        "stats":       stats,
        "findings":    unique[:500],  # cap for response size
    }


# ═══════════════════════════════════════════════════════════════════════════
# API: Triage — update finding status
# ═══════════════════════════════════════════════════════════════════════════

# In-memory triage store (keyed by fingerprint)
_TRIAGE: dict[str, str] = {}

@app.post("/api/triage")
async def update_triage(params: dict = Body(...)):
    """
    Update triage status for a vulnerability finding.
    Status: open | confirmed | resolved | risk_accepted | false_positive
    """
    fingerprint = params.get("fingerprint", "")
    status = params.get("status", "open")
    valid = {"open", "confirmed", "resolved", "risk_accepted", "false_positive"}
    if not fingerprint:
        raise HTTPException(400, "fingerprint обязателен")
    if status not in valid:
        raise HTTPException(400, f"Неверный статус. Допустимые: {', '.join(valid)}")
    _TRIAGE[fingerprint] = status
    return {"fingerprint": fingerprint, "status": status}


@app.get("/api/triage")
async def get_triage():
    """Get all triage statuses."""
    return {"triage": _TRIAGE, "count": len(_TRIAGE)}


# ═══════════════════════════════════════════════════════════════════════════
# API: Quality score endpoint for existing SBOM file
# ═══════════════════════════════════════════════════════════════════════════

@app.post("/api/quality")
async def check_sbom_quality(params: dict = Body(...)):
    """Run CISA 2025 quality check on an existing SBOM file."""
    sbom_path = params.get("sbom_path", "")
    if not sbom_path or not Path(sbom_path).exists():
        raise HTTPException(404, "SBOM файл не найден")

    # Create temporary job context for logging
    job_id = f"quality_{uuid.uuid4().hex[:8]}"
    _LOG_CACHE[job_id] = []
    quality = _quality_check(job_id, Path(sbom_path))
    stats = _collect_stats(Path(sbom_path))
    del _LOG_CACHE[job_id]
    return {"quality": quality, "stats": stats}


# ═══════════════════════════════════════════════════════════════════════════
# API: Available scanners/tools status
# ═══════════════════════════════════════════════════════════════════════════

@app.get("/api/tools")
async def tools_status():
    """Return availability of external tools."""
    import shutil as sh
    tools = {
        "cdxgen":       bool(sh.which("cdxgen")),
        "syft":         bool(sh.which("syft")),
        "grype":        bool(sh.which("grype")),
        "trivy":        bool(sh.which("trivy")),
        "osv-scanner":  bool(sh.which("osv-scanner")),
        "sbomqs":       bool(sh.which("sbomqs")),
        "cyclonedx":    bool(sh.which("cyclonedx")),
        "jq":           bool(sh.which("jq")),
    }
    return {"tools": tools, "bdu_available": BDU_AVAILABLE,
            "importers_ok": IMPORTERS_OK}


