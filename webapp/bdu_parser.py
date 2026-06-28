"""
BDU Parser — конвертер базы данных уязвимостей ФСТЭК (vulxml.xml) в SQLite.
Поддерживает streaming-парсинг 500+ MB XML без загрузки в RAM.
"""
import re
import sqlite3
import sys
import zipfile
from pathlib import Path
from typing import Iterator

DB_PATH = Path(__file__).parent / "bdu.db"


# ═══════════════════════════════════════════════════════════════════════════
# Streaming XML parser — не грузим весь файл в память
# ═══════════════════════════════════════════════════════════════════════════

def _re(pattern: str, text: str, default: str = "") -> str:
    m = re.search(pattern, text, re.DOTALL)
    return m.group(1).strip() if m else default


def _re_all(pattern: str, text: str) -> list[str]:
    return [m.strip() for m in re.findall(pattern, text, re.DOTALL)]


def _parse_vul(vul_xml: str) -> dict:
    """Парсит одну <vul>...</vul> запись в словарь."""
    # CVSS score из атрибута
    cvss_m = re.search(r'<vector\s+score="([^"]+)"', vul_xml)
    cvss_score = float(cvss_m.group(1)) if cvss_m else None
    cvss_vector = _re(r'<vector[^>]*>([^<]+)</vector>', vul_xml)

    # severity → нормализуем в english
    sev_raw = _re(r'<severity>([^<]+)</severity>', vul_xml)
    if   "Критическ" in sev_raw: severity = "critical"
    elif "Высокий"   in sev_raw: severity = "high"
    elif "Средний"   in sev_raw: severity = "medium"
    elif "Низкий"    in sev_raw: severity = "low"
    else:                         severity = "unknown"

    # exploit_status → булево
    exp_raw = _re(r'<exploit_status>([^<]+)</exploit_status>', vul_xml).lower()
    has_exploit = "существует" in exp_raw  # "Существует" / "Существует в открытом доступе"
    public_exploit = "открытом доступе" in exp_raw

    # CVE идентификаторы
    cve_ids = re.findall(r'type="CVE"[^>]*>([^<]+)</identifier>', vul_xml)

    # vulnerable_software — список затронутых компонентов
    soft_blocks = re.findall(r'<soft>(.*?)</soft>', vul_xml, re.DOTALL)
    softs = []
    for sb in soft_blocks:
        name    = _re(r'<name>([^<]*)</name>', sb)
        vendor  = _re(r'<vendor>([^<]*)</vendor>', sb)
        version = _re(r'<version>([^<]*)</version>', sb)
        platform = _re(r'<platform>([^<]*)</platform>', sb)
        softs.append({"name": name, "vendor": vendor, "version": version, "platform": platform})

    # CWE
    cwes = re.findall(r'<cwe>.*?<identifier>(CWE-\d+)</identifier>', vul_xml, re.DOTALL)

    return {
        "bdu_id":        _re(r'<identifier>(BDU:[^<]+)</identifier>', vul_xml),
        "name":          _re(r'<name>([^<]+)</name>', vul_xml),
        "description":   _re(r'<description>([^<]+)</description>', vul_xml),
        "severity":      severity,
        "severity_raw":  sev_raw[:200],
        "cvss_score":    cvss_score,
        "cvss_vector":   cvss_vector,
        "has_exploit":   has_exploit,
        "public_exploit":public_exploit,
        "exploit_raw":   _re(r'<exploit_status>([^<]+)</exploit_status>', vul_xml),
        "fix_status":    _re(r'<fix_status>([^<]+)</fix_status>', vul_xml),
        "solution":      _re(r'<solution>([^<]+)</solution>', vul_xml),
        "vul_class":     _re(r'<vul_class>([^<]+)</vul_class>', vul_xml),
        "vul_status":    _re(r'<vul_status>([^<]+)</vul_status>', vul_xml),
        "pub_date":      _re(r'<publication_date>([^<]+)</publication_date>', vul_xml),
        "upd_date":      _re(r'<last_upd_date>([^<]+)</last_upd_date>', vul_xml),
        "sources":       _re(r'<sources>([^<]+)</sources>', vul_xml),
        "cve_ids":       cve_ids,
        "cwes":          cwes,
        "softs":         softs,
    }


def _stream_vuls(xml_stream) -> Iterator[dict]:
    """Потоково читает XML и выдаёт распарсенные записи."""
    buf = ""
    for raw in xml_stream:
        buf += raw.decode("utf-8", errors="replace")
        while "<identifier>BDU:" in buf and "</vul>" in buf:
            # Берём первую полную запись
            start = buf.find("<vul>")
            end   = buf.find("</vul>", start) + 6
            if start < 0 or end < 6:
                break
            vul_xml = buf[start:end]
            buf     = buf[end:]
            try:
                yield _parse_vul(vul_xml)
            except Exception:
                pass


# ═══════════════════════════════════════════════════════════════════════════
# SQLite схема
# ═══════════════════════════════════════════════════════════════════════════

SCHEMA = """
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    bdu_id          TEXT UNIQUE NOT NULL,
    name            TEXT,
    description     TEXT,
    severity        TEXT,          -- critical/high/medium/low
    severity_raw    TEXT,
    cvss_score      REAL,
    cvss_vector     TEXT,
    has_exploit     INTEGER,       -- 0/1
    public_exploit  INTEGER,       -- 0/1
    exploit_raw     TEXT,
    fix_status      TEXT,
    solution        TEXT,
    vul_class       TEXT,
    vul_status      TEXT,
    pub_date        TEXT,
    upd_date        TEXT,
    sources         TEXT
);

CREATE TABLE IF NOT EXISTS cve_mapping (
    vul_id  INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cve_id  TEXT NOT NULL,
    PRIMARY KEY (vul_id, cve_id)
);

CREATE TABLE IF NOT EXISTS cwe_mapping (
    vul_id  INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    cwe_id  TEXT NOT NULL,
    PRIMARY KEY (vul_id, cwe_id)
);

-- Таблица уязвимых компонентов для matching по SBOM
CREATE TABLE IF NOT EXISTS affected_software (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    vul_id    INTEGER REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    name      TEXT,
    name_norm TEXT,   -- lowercase, trimmed
    vendor    TEXT,
    vendor_norm TEXT, -- lowercase, trimmed
    version   TEXT
);

CREATE INDEX IF NOT EXISTS idx_cve      ON cve_mapping(cve_id);
CREATE INDEX IF NOT EXISTS idx_affected_name   ON affected_software(name_norm);
CREATE INDEX IF NOT EXISTS idx_affected_vendor ON affected_software(vendor_norm);
CREATE INDEX IF NOT EXISTS idx_severity ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_exploit  ON vulnerabilities(has_exploit);

-- Метаинфо об импорте
CREATE TABLE IF NOT EXISTS import_meta (
    key   TEXT PRIMARY KEY,
    value TEXT
);
"""


def build_db(xml_source: str | Path, db_path: Path = DB_PATH,
             progress_cb=None) -> int:
    """
    Импортирует vulxml.xml (или .zip с ним) в SQLite.
    Возвращает число загруженных записей.
    """
    db_path = Path(db_path)
    db_path.unlink(missing_ok=True)

    con = sqlite3.connect(db_path)
    con.executescript(SCHEMA)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA synchronous=NORMAL")

    src = Path(xml_source)
    count = 0
    BATCH = 1000

    def open_source():
        if src.suffix == ".zip":
            zf = zipfile.ZipFile(src)
            name = next(n for n in zf.namelist() if n.endswith(".xml"))
            return zf.open(name)
        return open(src, "rb")

    vul_rows  = []
    cve_rows  = []
    cwe_rows  = []
    soft_rows = []

    with open_source() as f:
        for v in _stream_vuls(f):
            count += 1

            vul_rows.append((
                v["bdu_id"], v["name"], v["description"],
                v["severity"], v["severity_raw"],
                v["cvss_score"], v["cvss_vector"],
                int(v["has_exploit"]), int(v["public_exploit"]),
                v["exploit_raw"], v["fix_status"], v["solution"],
                v["vul_class"], v["vul_status"],
                v["pub_date"], v["upd_date"], v["sources"],
            ))

            if len(vul_rows) >= BATCH:
                _flush(con, vul_rows, cve_rows, cwe_rows, soft_rows)
                vul_rows = cve_rows = cwe_rows = soft_rows = []
                if progress_cb:
                    progress_cb(count)

            # Накапливаем mapping-ы (нужен id из БД — вставим после flush)
            for cve in v["cve_ids"]:
                cve_rows.append((v["bdu_id"], cve.strip()))
            for cwe in v["cwes"]:
                cwe_rows.append((v["bdu_id"], cwe.strip()))
            for s in v["softs"]:
                soft_rows.append((
                    v["bdu_id"],
                    s["name"], s["name"].lower().strip(),
                    s["vendor"], s["vendor"].lower().strip(),
                    s["version"],
                ))

    if vul_rows:
        _flush(con, vul_rows, cve_rows, cwe_rows, soft_rows)

    import datetime
    con.execute("INSERT OR REPLACE INTO import_meta VALUES ('count', ?)", (str(count),))
    con.execute("INSERT OR REPLACE INTO import_meta VALUES ('imported_at', ?)",
                (datetime.datetime.utcnow().isoformat(),))
    con.execute("INSERT OR REPLACE INTO import_meta VALUES ('source', ?)", (str(src.name),))
    con.commit()
    con.close()
    return count


def _flush(con, vul_rows, cve_rows, cwe_rows, soft_rows):
    """Batch-вставка в транзакции."""
    with con:
        con.executemany("""
            INSERT OR IGNORE INTO vulnerabilities
            (bdu_id, name, description, severity, severity_raw,
             cvss_score, cvss_vector, has_exploit, public_exploit,
             exploit_raw, fix_status, solution, vul_class, vul_status,
             pub_date, upd_date, sources)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, vul_rows)

        # Получаем id-шники только что вставленных записей
        bdu_to_id = {}
        bdu_ids_batch = [r[0] for r in vul_rows]
        for row in con.execute(
            f"SELECT id, bdu_id FROM vulnerabilities WHERE bdu_id IN ({','.join('?'*len(bdu_ids_batch))})",
            bdu_ids_batch
        ):
            bdu_to_id[row[1]] = row[0]

        con.executemany("""
            INSERT OR IGNORE INTO cve_mapping (vul_id, cve_id)
            VALUES (?, ?)
        """, [(bdu_to_id[b], c) for b, c in cve_rows if b in bdu_to_id])

        con.executemany("""
            INSERT OR IGNORE INTO cwe_mapping (vul_id, cwe_id)
            VALUES (?, ?)
        """, [(bdu_to_id[b], c) for b, c in cwe_rows if b in bdu_to_id])

        con.executemany("""
            INSERT INTO affected_software (vul_id, name, name_norm, vendor, vendor_norm, version)
            VALUES (?, ?, ?, ?, ?, ?)
        """, [(bdu_to_id[b], n, nn, vn, vnn, ver) for b, n, nn, vn, vnn, ver in soft_rows if b in bdu_to_id])


def get_meta(db_path: Path = DB_PATH) -> dict:
    """Возвращает метаинформацию об импорте."""
    if not db_path.exists():
        return {}
    try:
        con = sqlite3.connect(db_path)
        rows = con.execute("SELECT key, value FROM import_meta").fetchall()
        con.close()
        return dict(rows)
    except Exception:
        return {}


def db_exists(db_path: Path = DB_PATH) -> bool:
    if not db_path.exists():
        return False
    try:
        con = sqlite3.connect(db_path)
        count = con.execute("SELECT value FROM import_meta WHERE key='count'").fetchone()
        con.close()
        return count is not None
    except Exception:
        return False


if __name__ == "__main__":
    src = sys.argv[1] if len(sys.argv) > 1 else "/root/sbomsauto/vulxml.zip"
    print(f"Импорт BDU из {src} ...")

    def progress(n):
        print(f"  {n:,} записей...", end="\r", flush=True)

    total = build_db(src, progress_cb=progress)
    print(f"\nГотово: {total:,} уязвимостей загружено в {DB_PATH}")
