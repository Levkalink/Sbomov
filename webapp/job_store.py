"""Persistent SQLite storage for SBOM jobs (survives server restart)."""
import json
import sqlite3
import time
from pathlib import Path
from typing import Optional

_DB: Optional[Path] = None
_SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id          TEXT PRIMARY KEY,
    status      TEXT NOT NULL DEFAULT 'pending',
    created_at  REAL NOT NULL,
    output_dir  TEXT NOT NULL,
    params      TEXT,
    logs        TEXT,           -- JSON array of log lines
    stats       TEXT,
    quality     TEXT,
    output_files TEXT,
    checker_passed INTEGER,
    final_sbom  TEXT,
    detected_languages TEXT
);
CREATE INDEX IF NOT EXISTS idx_jobs_created ON jobs(created_at DESC);
"""


def init(db_path: Path):
    global _DB
    _DB = db_path
    con = sqlite3.connect(_DB)
    con.executescript(_SCHEMA)
    con.close()


def _con() -> sqlite3.Connection:
    c = sqlite3.connect(_DB)
    c.row_factory = sqlite3.Row
    return c


def create_job(job_id: str, output_dir: str, params: dict) -> dict:
    now = time.time()
    j = {
        "id": job_id,
        "status": "pending",
        "created_at": now,
        "output_dir": output_dir,
        "params": params,
        "logs": [],
        "stats": {},
        "quality": {},
        "output_files": [],
        "checker_passed": None,
        "final_sbom": None,
        "detected_languages": [],
    }
    with _con() as con:
        con.execute("""
            INSERT INTO jobs (id, status, created_at, output_dir, params, logs,
                              stats, quality, output_files, checker_passed,
                              final_sbom, detected_languages)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            job_id, "pending", now, output_dir,
            json.dumps(params), json.dumps([]),
            json.dumps({}), json.dumps({}), json.dumps([]),
            None, None, json.dumps([]),
        ))
    return j


def get_job(job_id: str) -> Optional[dict]:
    with _con() as con:
        row = con.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return None
    return _row_to_dict(row)


def list_jobs(limit: int = 200) -> list[dict]:
    with _con() as con:
        rows = con.execute(
            "SELECT * FROM jobs ORDER BY created_at DESC LIMIT ?", (limit,)
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_job(job_id: str, **kwargs):
    """Update specific fields. Handles JSON serialization for dict/list fields."""
    if not kwargs:
        return
    cols = []
    vals = []
    for k, v in kwargs.items():
        if isinstance(v, (dict, list)):
            v = json.dumps(v)
        cols.append(f"{k}=?")
        vals.append(v)
    vals.append(job_id)
    with _con() as con:
        con.execute(f"UPDATE jobs SET {', '.join(cols)} WHERE id=?", vals)


def append_log(job_id: str, line: str):
    with _con() as con:
        row = con.execute("SELECT logs FROM jobs WHERE id=?", (job_id,)).fetchone()
        if row:
            logs = json.loads(row[0] or "[]")
            logs.append(line)
            con.execute("UPDATE jobs SET logs=? WHERE id=?",
                        (json.dumps(logs), job_id))


def get_logs(job_id: str) -> list[str]:
    with _con() as con:
        row = con.execute("SELECT logs FROM jobs WHERE id=?", (job_id,)).fetchone()
    if not row:
        return []
    return json.loads(row[0] or "[]")


def _row_to_dict(row) -> dict:
    d = dict(row)
    for field in ("params", "logs", "stats", "quality", "output_files", "detected_languages"):
        if d.get(field) is not None:
            try:
                d[field] = json.loads(d[field])
            except Exception:
                pass
    return d
