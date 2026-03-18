"""SQLite persistence for LLMObs spans (load on startup, append on decode)."""

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

log = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".ddapm-test-agent" / "llmobs.db"


def _ensure_db_dir(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def init_llmobs_db(db_path: Optional[str] = None) -> sqlite3.Connection:
    """Create or open SQLite DB and ensure llmobs_spans table exists."""
    path = Path(db_path) if db_path else DEFAULT_DB_PATH
    _ensure_db_dir(path)
    conn = sqlite3.connect(str(path))
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS llmobs_spans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            span_id TEXT UNIQUE,
            span_json TEXT NOT NULL,
            created_at REAL
        )
        """
    )
    conn.commit()
    log.info("LLMObs persistence initialized db_path=%s", path.resolve())
    return conn


def upsert_spans(conn: sqlite3.Connection, spans: List[Dict[str, Any]]) -> None:
    """Insert or update spans by span_id. Updates existing rows with merged content."""
    if not spans:
        return
    now = time.time()
    updated_count = 0
    inserted_count = 0
    for s in spans:
        span_id = s.get("span_id")
        if span_id is None:
            continue
        span_id_str = str(span_id)
        duration = s.get("duration")
        span_json = json.dumps(s)
        cur = conn.execute(
            "UPDATE llmobs_spans SET span_json = ?, created_at = ? WHERE span_id = ?",
            (span_json, now, span_id_str),
        )
        if cur.rowcount == 0:
            conn.execute(
                "INSERT INTO llmobs_spans (span_id, span_json, created_at) VALUES (?, ?, ?)",
                (span_id_str, span_json, now),
            )
            inserted_count += 1
            log.debug("upsert span_id=%s INSERT duration=%s", span_id_str, duration)
        else:
            updated_count += 1
            log.debug("upsert span_id=%s UPDATE duration=%s", span_id_str, duration)
    conn.commit()
    if updated_count or inserted_count:
        log.info("upsert_spans total=%d updated=%d inserted=%d", len(spans), updated_count, inserted_count)


def load_all_spans(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Load all persisted spans from the DB (for startup)."""
    rows = conn.execute("SELECT span_json FROM llmobs_spans ORDER BY id").fetchall()
    result: List[Dict[str, Any]] = []
    for (span_json,) in rows:
        try:
            result.append(json.loads(span_json))
        except (json.JSONDecodeError, TypeError):
            continue
    log.info("load_all_spans count=%d", len(result))
    return result
