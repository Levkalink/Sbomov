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

# BDU модули
sys.path.insert(0, str(Path(__file__).parent))
try:
    from bdu_parser  import build_db, db_exists, get_meta, DB_PATH as BDU_DB
    from bdu_matcher import scan_sbom, get_stats, match_component
    BDU_AVAILABLE = True
except ImportError as _e:
    BDU_AVAILABLE = False
    BDU_DB = Path(__file__).parent / "bdu.db"

# Задания BDU (импорт и сканирование)
BDU_JOBS: dict[str, dict] = {}

# ─── Пути ───────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).parent
CHECKER_DIR = BASE_DIR.parent / "sbom-checker-master"
JOBS_DIR    = BASE_DIR / "jobs"
JOBS_DIR.mkdir(exist_ok=True)

PYTHON     = sys.executable
CHECKER_PY = CHECKER_DIR / "sbom-checker.py"
UPDATER_PY = CHECKER_DIR / "sbom-updater.py"
TO_CSV_PY  = CHECKER_DIR / "sbom-to-csv.py"
TO_ODT_PY  = CHECKER_DIR / "sbom-to-odt.py"

# sbom_utils живёт рядом с checker — добавляем в PYTHONPATH для subprocess
CHECKER_ENV = {**os.environ, "PYTHONPATH": str(CHECKER_DIR)}

# ─── Хранилище заданий ──────────────────────────────────────────────────────
JOBS: dict[str, dict] = {}

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

    # Определяем тип по имени файла (не только по последнему расширению)
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

    # Если архив содержит ровно одну папку — входим в неё
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
# Pipeline helpers
# ═══════════════════════════════════════════════════════════════════════════
def _log(job_id: str, line: str):
    JOBS[job_id]["logs"].append(line)

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
    """Удаляем системные deb/rpm/apk пакеты через jq."""
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


def _quality_check(job_id: str, sbom_path: Path) -> dict:
    """
    Проверка качества SBOM по стандартам:
    - CISA 2025 Minimum Elements
    - NTIA Minimum Elements
    - CycloneDX best practices
    Возвращает dict с результатами и score 0-100.
    """
    _log(job_id, "\n" + "═" * 60)
    _log(job_id, "▶ ШАГ 5: Проверка качества SBOM (CISA 2025)")
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

    # ── Документ-уровень ────────────────────────────────────────────────
    chk("bomFormat = CycloneDX",     data.get("bomFormat") == "CycloneDX", critical=True)
    chk("specVersion присутствует",  bool(data.get("specVersion")), critical=True)
    chk("serialNumber (UUID)",        bool(data.get("serialNumber")), "urn:uuid:…")
    chk("version (целое число)",      isinstance(data.get("version"), int))
    chk("metadata.timestamp",         bool(meta.get("timestamp")),
        detail=meta.get("timestamp", "ОТСУТСТВУЕТ"), critical=True)

    # CISA 2025: инструмент генерации
    tools = meta.get("tools", {})
    has_tools = bool(tools.get("components") or tools.get("services") or isinstance(tools, list))
    chk("metadata.tools (CISA 2025)", has_tools, "наименование инструмента генерации")

    # CISA 2025: supplier/manufacturer
    mfr = meta.get("manufacture") or meta.get("manufacturer") or meta.get("supplier")
    chk("metadata.manufacture/supplier (CISA 2025)", bool(mfr))

    # metadata.component (описание самого продукта)
    mc = meta.get("component", {})
    chk("metadata.component.name",    bool(mc.get("name")), critical=True)
    chk("metadata.component.version", bool(mc.get("version")))

    if total == 0:
        _log(job_id, "  ⚠ В SBOM нет компонентов!")
        chk("Есть компоненты", False, "список components пуст", critical=True)
        score = 10 if all(c["passed"] for c in checks if c["critical"]) else 0
        return {"score": score, "checks": checks, "total": 0}

    # ── Покрытие компонентов ─────────────────────────────────────────────
    def pct(lst): return f"{sum(lst)}/{total} ({100*sum(lst)//total}%)"

    has_purl    = [bool(c.get("purl"))    for c in comps]
    has_ver     = [bool(c.get("version")) for c in comps]
    has_lic     = [bool(c.get("licenses")) for c in comps]
    has_hash    = [bool(c.get("hashes"))  for c in comps]
    has_name    = [bool(c.get("name"))    for c in comps]
    has_type    = [bool(c.get("type"))    for c in comps]
    has_refs    = [bool(c.get("externalReferences")) for c in comps]

    chk("Все компоненты имеют name",    all(has_name),    pct(has_name),    critical=True)
    chk("PURL (NTIA / CISA 2025)",      all(has_purl),    pct(has_purl),    critical=True)
    chk("Version (NTIA / CISA 2025)",   all(has_ver),     pct(has_ver),     critical=True)
    chk("Hash SHA-256 (CISA 2025 new)", all(has_hash),    pct(has_hash))
    chk("Licenses (CISA 2025 new)",     all(has_lic),     pct(has_lic))
    chk("type (library/framework/…)",   all(has_type),    pct(has_type))
    chk("externalReferences (VCS)",     sum(has_refs) > 0, pct(has_refs))

    # Проверка корректности PURL-формата
    bad_purl = [c["purl"] for c in comps if c.get("purl") and not c["purl"].startswith("pkg:")]
    chk("PURL-формат (pkg:…)",          len(bad_purl) == 0,
        f"неверных: {len(bad_purl)}" if bad_purl else "")

    # dependencies секция
    chk("dependencies (граф зависимостей)", bool(data.get("dependencies")))

    # ── Итоговый score ───────────────────────────────────────────────────
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
    }
    earned = sum(w for c in checks if c["passed"] for name, w in weights.items() if name == c["name"])
    max_w  = sum(weights.values())
    score  = round(100 * earned / max_w)
    _log(job_id, f"\n  📊 Quality Score: {score}/100")
    return {"score": score, "checks": checks, "total": total}


# ═══════════════════════════════════════════════════════════════════════════
# Main Pipeline (runs in thread via BackgroundTasks)
# ═══════════════════════════════════════════════════════════════════════════
def _pipeline(job_id: str, params: dict):
    j = JOBS[job_id]
    j["status"] = "running"
    out_dir = Path(j["output_dir"])
    mode = params.get("mode", "both")

    try:
        generated_sbom: Optional[Path] = None

        # ── ШАГ 1: Генерация ────────────────────────────────────────────
        if mode in ("generate", "both"):
            _log(job_id, "═" * 60)
            _log(job_id, "▶ ШАГ 1: Генерация SBOM")
            _log(job_id, "═" * 60)

            project_path = params.get("project_path", "").strip()
            if not project_path or not Path(project_path).exists():
                _log(job_id, f"✗ Путь не найден: {project_path!r}")
                j["status"] = "error"
                return

            p = Path(project_path)
            spec_ver  = str(params.get("spec_version", "1.6"))
            proj_name = (params.get("project_name") or p.name).strip() or "project"
            proj_ver  = (params.get("project_version") or "0.0.0").strip()
            scanner   = params.get("scanner", "cdxgen")
            raw_out   = out_dir / "sbom-raw.json"

            if scanner == "cdxgen":
                filters = []
                if params.get("filter_deb", True):  filters += ["--filter", "pkg:deb"]
                if params.get("filter_rpm", True):  filters += ["--filter", "pkg:rpm"]
                if params.get("filter_apk", True):  filters += ["--filter", "pkg:apk"]
                extra = ["--required-only"] if params.get("required_only") else []

                rc = _run(job_id, [
                    "cdxgen",
                    "--type",             params.get("project_type", "c"),
                    "--spec-version",     spec_ver,
                    "--output",           str(raw_out),
                    "--project-name",     proj_name,
                    "--project-version",  proj_ver,
                    *filters, *extra,
                    project_path,
                ], env={**os.environ})

                if rc != 0:
                    _log(job_id, f"⚠  cdxgen завершился с кодом {rc}")

            elif scanner == "syft":
                has_conan = (p / "conanfile.py").exists() or (p / "conanfile.txt").exists()
                catalogers = "conan-cataloger,binary-cataloger" if has_conan else "binary-cataloger"
                _run(job_id, [
                    "syft", f"dir:{project_path}",
                    "--output", f"cyclonedx-json@{spec_ver}={raw_out}",
                    "--override-default-catalogers", catalogers,
                    "--exclude", "/usr/share/**",
                    "--exclude", "/var/**", "--exclude", "/etc/**",
                ], env={**os.environ})

            if raw_out.exists() and raw_out.stat().st_size > 10:
                generated_sbom = raw_out
                _log(job_id, "\n▶ Фильтрация системных пакетов...")
                filtered = out_dir / "sbom-filtered.json"
                _filter_noise(job_id, raw_out, filtered)
                if filtered.exists() and filtered.stat().st_size > 10:
                    generated_sbom = filtered
            else:
                _log(job_id, "✗ SBOM не создан (файл пуст или отсутствует)")

        # ── ШАГ 2: Определяем SBOM для обработки ───────────────────────
        sbom_in: Optional[Path] = None
        if mode == "validate":
            inp = params.get("input_sbom", "").strip()
            sbom_in = Path(inp) if inp and Path(inp).exists() else None
            if not sbom_in:
                _log(job_id, "✗ Файл для валидации не найден")
                j["status"] = "error"
                return
        else:
            sbom_in = generated_sbom

        if not sbom_in:
            _log(job_id, "✗ Нет SBOM-файла для обработки")
            j["status"] = "error"
            return

        # ── ШАГ 3: sbom-updater (обогащение) ────────────────────────────
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
            rc = _run(job_id, cmd, cwd=str(CHECKER_DIR))
            if enriched_out.exists() and enriched_out.stat().st_size > 10:
                enriched = enriched_out
                _log(job_id, f"✓ Обогащение выполнено → {enriched_out.name}")
            else:
                _log(job_id, "⚠  sbom-updater не создал файл, использую исходный")
                enriched = sbom_in

        final_sbom = enriched or sbom_in

        # ── ШАГ 4: sbom-checker (валидация схемы) ───────────────────────
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

        # ── ШАГ 5: CISA 2025 quality check ──────────────────────────────
        quality = _quality_check(job_id, final_sbom)

        # ── ШАГ 6: Экспорт CSV + ODT ────────────────────────────────────
        _log(job_id, "\n" + "═" * 60)
        _log(job_id, "▶ ШАГ 4: Экспорт (CSV, ODT)")
        _log(job_id, "═" * 60)

        csv_out = out_dir / "sbom.csv"
        _run(job_id, [PYTHON, str(TO_CSV_PY), str(final_sbom), str(csv_out)],
             cwd=str(CHECKER_DIR))
        if csv_out.exists(): _log(job_id, f"✓ CSV: {csv_out.name}")

        # odt_format: убираем "2025" суффикс, получаем "oss" или "container"
        checker_format = params.get("checker_format", "oss")
        odt_format = checker_format.replace("2025", "")
        if not odt_format:
            odt_format = "oss"

        odt_out = out_dir / "sbom.odt"
        _run(job_id, [PYTHON, str(TO_ODT_PY), "--format", odt_format,
                      str(final_sbom), str(odt_out)], cwd=str(CHECKER_DIR))
        if odt_out.exists(): _log(job_id, f"✓ ODT: {odt_out.name}")

        # ── Сбор статистики ──────────────────────────────────────────────
        stats = _collect_stats(final_sbom)

        j.update({
            "status":        "done",
            "stats":         stats,
            "quality":       quality,
            "output_files":  [f.name for f in out_dir.iterdir() if f.is_file()],
            "checker_passed": checker_passed,
            "final_sbom":    final_sbom.name,
        })
        _log(job_id, "\n" + "═" * 60)
        _log(job_id, "✓ Pipeline завершён успешно")
        _log(job_id, "═" * 60)

    except Exception as exc:
        j["status"] = "error"
        _log(job_id, f"\n✗ КРИТИЧЕСКАЯ ОШИБКА: {exc}")
        import traceback
        _log(job_id, traceback.format_exc())


def _collect_stats(sbom_path: Path) -> dict:
    try:
        with open(sbom_path, encoding="utf-8") as f:
            data = json.load(f)
        comps = data.get("components", [])
        return {
            "total":        len(comps),
            "with_purl":    sum(1 for c in comps if c.get("purl")),
            "with_version": sum(1 for c in comps if c.get("version")),
            "with_license": sum(1 for c in comps if c.get("licenses")),
            "with_hash":    sum(1 for c in comps if c.get("hashes")),
            "with_refs":    sum(1 for c in comps if c.get("externalReferences")),
            "spec_version": data.get("specVersion", "?"),
            "components": [
                {
                    "name":     c.get("name", ""),
                    "version":  c.get("version", ""),
                    "purl":     c.get("purl", ""),
                    "type":     c.get("type", ""),
                    "licenses": ", ".join(
                        l.get("license", {}).get("id") or l.get("license", {}).get("name", "")
                        for l in (c.get("licenses") or []) if isinstance(l, dict)
                    ),
                }
                for c in comps[:500]
            ],
        }
    except Exception:
        return {}


# ═══════════════════════════════════════════════════════════════════════════
# API: запуск задания
# ═══════════════════════════════════════════════════════════════════════════
@app.post("/api/run")
async def run_job(background_tasks: BackgroundTasks, params: dict = Body(...)):
    job_id = uuid.uuid4().hex[:12]
    out_dir = JOBS_DIR / job_id
    out_dir.mkdir()

    JOBS[job_id] = {
        "id":            job_id,
        "status":        "pending",
        "logs":          [],
        "output_dir":    str(out_dir),
        "stats":         {},
        "quality":       {},
        "output_files":  [],
        "checker_passed": None,
        "final_sbom":    None,
        "created_at":    time.time(),
        "params":        params,
    }
    background_tasks.add_task(_pipeline, job_id, params)
    return {"job_id": job_id}


# ═══════════════════════════════════════════════════════════════════════════
# API: SSE log stream
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/stream/{job_id}")
async def stream_logs(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404)

    async def gen():
        sent = 0
        while True:
            j = JOBS.get(job_id, {})
            logs = j.get("logs", [])
            while sent < len(logs):
                yield f"data: {json.dumps(logs[sent])}\n\n"
                sent += 1
            if j.get("status") in ("done", "error") and sent >= len(logs):
                yield "data: __DONE__\n\n"
                break
            await asyncio.sleep(0.15)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# ═══════════════════════════════════════════════════════════════════════════
# API: статус задания
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/job/{job_id}")
async def get_job(job_id: str):
    if job_id not in JOBS:
        raise HTTPException(404)
    j = JOBS[job_id]
    return {
        "id":             j["id"],
        "status":         j["status"],
        "stats":          j["stats"],
        "quality":        j["quality"],
        "output_files":   j["output_files"],
        "checker_passed": j["checker_passed"],
        "final_sbom":     j["final_sbom"],
    }


# ═══════════════════════════════════════════════════════════════════════════
# API: скачать файл
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/download/{job_id}/{filename}")
async def download_file(job_id: str, filename: str):
    if job_id not in JOBS:
        raise HTTPException(404)
    # path traversal guard
    path = (Path(JOBS[job_id]["output_dir"]) / filename).resolve()
    if not str(path).startswith(str(JOBS_DIR)):
        raise HTTPException(403)
    if not path.is_file():
        raise HTTPException(404, "Файл не найден")
    return FileResponse(path, filename=filename)


# ═══════════════════════════════════════════════════════════════════════════
# API: история заданий
# ═══════════════════════════════════════════════════════════════════════════
@app.get("/api/jobs")
async def list_jobs():
    return sorted(
        [{"id": j["id"], "status": j["status"],
          "created_at": j["created_at"],
          "project": j["params"].get("project_name") or j["params"].get("app_name", "?"),
          "quality_score": j.get("quality", {}).get("score")}
         for j in JOBS.values()],
        key=lambda x: x["created_at"], reverse=True
    )


# ═══════════════════════════════════════════════════════════════════════════
# BDU API
# ═══════════════════════════════════════════════════════════════════════════

def _bdu_import_task(task_id: str, zip_path: str):
    """Фоновый импорт BDU XML в SQLite."""
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
    """Статус базы данных BDU."""
    if not BDU_AVAILABLE:
        return {"available": False, "error": "bdu_parser модуль недоступен"}
    stats = get_stats(BDU_DB)
    meta  = get_meta(BDU_DB)
    return {"available": True, "db_exists": db_exists(BDU_DB),
            "stats": stats, "meta": meta}


@app.post("/api/bdu/import")
async def bdu_import(background_tasks: BackgroundTasks, params: dict = Body(...)):
    """Запускает импорт BDU XML/ZIP в SQLite."""
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
    """SSE-стрим прогресса импорта BDU."""
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
    """Сканирует SBOM-файл против базы BDU."""
    if not BDU_AVAILABLE:
        raise HTTPException(503, "bdu_matcher недоступен")
    if not db_exists(BDU_DB):
        raise HTTPException(409, "База BDU не загружена. Сначала выполните импорт.")

    # Получаем SBOM файл — либо из job, либо прямой путь
    sbom_path: Optional[Path] = None
    job_id = params.get("job_id")
    if job_id and job_id in JOBS:
        final_sbom = JOBS[job_id].get("final_sbom")
        if final_sbom:
            sbom_path = Path(JOBS[job_id]["output_dir"]) / final_sbom
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
                f"{s['total_vulns']} всего (critical={s['critical']}, high={s['high']})"
            )
        except Exception as e:
            BDU_JOBS[task_id]["status"] = "error"
            BDU_JOBS[task_id]["logs"].append(f"✗ Ошибка: {e}")

    background_tasks.add_task(_do_scan)
    return {"task_id": task_id}


@app.get("/api/bdu/scan/{task_id}")
async def bdu_scan_result(task_id: str):
    """Возвращает результат BDU-сканирования."""
    if task_id not in BDU_JOBS:
        raise HTTPException(404)
    j = BDU_JOBS[task_id]
    return {"status": j["status"], "logs": j.get("logs", []), "result": j.get("result")}


@app.get("/api/bdu/search")
async def bdu_search(q: str, limit: int = 10):
    """Поиск уязвимостей по имени компонента."""
    if not BDU_AVAILABLE or not db_exists(BDU_DB):
        raise HTTPException(409, "База BDU не загружена")
    results = match_component(name=q, limit=limit, db_path=BDU_DB)
    return {"results": results}
