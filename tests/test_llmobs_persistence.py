"""Unit tests for LLMObs SQLite persistence."""

import json
import sqlite3
from pathlib import Path

import pytest

from ddapm_test_agent.llmobs_persistence import init_llmobs_db
from ddapm_test_agent.llmobs_persistence import load_all_spans
from ddapm_test_agent.llmobs_persistence import upsert_spans


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "llmobs.db"


@pytest.fixture
def conn(db_path: Path) -> sqlite3.Connection:
    return init_llmobs_db(str(db_path))


def test_init_creates_db_and_table(conn: sqlite3.Connection, db_path: Path) -> None:
    assert db_path.exists()
    cur = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='llmobs_spans'")
    assert cur.fetchone() is not None
    cur = conn.execute("PRAGMA table_info(llmobs_spans)")
    columns = {row[1] for row in cur.fetchall()}
    assert columns >= {"id", "span_id", "span_json", "created_at"}


def test_init_idempotent(db_path: Path) -> None:
    c1 = init_llmobs_db(str(db_path))
    c2 = init_llmobs_db(str(db_path))
    c1.close()
    c2.close()


def test_upsert_spans_empty(conn: sqlite3.Connection) -> None:
    upsert_spans(conn, [])
    rows = conn.execute("SELECT COUNT(*) FROM llmobs_spans").fetchone()
    assert rows[0] == 0


def test_upsert_spans_skips_missing_span_id(conn: sqlite3.Connection) -> None:
    upsert_spans(conn, [{"name": "x", "duration": 1}])
    rows = conn.execute("SELECT COUNT(*) FROM llmobs_spans").fetchone()
    assert rows[0] == 0


def test_upsert_new_span_insert(conn: sqlite3.Connection) -> None:
    upsert_spans(conn, [{"span_id": "s1", "duration": 0}])
    loaded = load_all_spans(conn)
    assert len(loaded) == 1
    assert loaded[0]["span_id"] == "s1"
    assert loaded[0]["duration"] == 0


def test_upsert_same_span_id_updates(conn: sqlite3.Connection) -> None:
    upsert_spans(conn, [{"span_id": "s1", "duration": 0}])
    upsert_spans(conn, [{"span_id": "s1", "duration": 5}])
    loaded = load_all_spans(conn)
    assert len(loaded) == 1
    assert loaded[0]["duration"] == 5


def test_upsert_span_id_int_and_str_same_row(conn: sqlite3.Connection) -> None:
    upsert_spans(conn, [{"span_id": 123, "x": 1}])
    upsert_spans(conn, [{"span_id": "123", "x": 2}])
    loaded = load_all_spans(conn)
    assert len(loaded) == 1
    assert loaded[0]["x"] == 2


def test_load_all_spans_skips_bad_json(conn: sqlite3.Connection) -> None:
    conn.execute(
        "INSERT INTO llmobs_spans (span_id, span_json, created_at) VALUES (?, ?, ?)",
        ("bad", "not valid json", 0.0),
    )
    conn.execute(
        "INSERT INTO llmobs_spans (span_id, span_json, created_at) VALUES (?, ?, ?)",
        ("ok", json.dumps({"span_id": "ok", "duration": 1}), 0.0),
    )
    conn.commit()
    loaded = load_all_spans(conn)
    assert len(loaded) == 1
    assert loaded[0]["span_id"] == "ok"


def test_load_all_spans_order(conn: sqlite3.Connection) -> None:
    upsert_spans(conn, [{"span_id": "s1"}, {"span_id": "s2"}, {"span_id": "s3"}])
    loaded = load_all_spans(conn)
    assert [s["span_id"] for s in loaded] == ["s1", "s2", "s3"]
