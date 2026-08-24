"""Shared helpers for server-side historical session backfills."""

import json
import secrets
from typing import Any
from typing import Dict
from typing import List


def format_trace_id() -> str:
    return f"{secrets.randbits(128):032x}"


def format_span_id() -> str:
    return str(secrets.randbits(63))


def to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value)
    except Exception:
        return str(value)


def backfill_metadata(*, input_messages_unavailable: bool = False) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {"backfilled": True}
    if input_messages_unavailable:
        metadata["backfill"] = {
            "limitations": {
                "input_messages_unavailable": True,
            },
        }
    return metadata


def has_backfilled_session(spans: List[Dict[str, Any]], session_id: str) -> bool:
    for span in spans:
        if span.get("session_id") != session_id:
            continue
        tags = span.get("tags") or []
        metadata = span.get("meta", {}).get("metadata", {})
        dd_metadata = metadata.get("_dd", {}) if isinstance(metadata, dict) else {}
        if "backfilled:true" in tags or dd_metadata.get("backfilled") is True:
            return True
    return False
