"""LLMObs wire-format decoding and SDK span normalization."""

import gzip
import json
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Set
from typing import Tuple

import msgpack


log = logging.getLogger(__name__)


def decode_llmobs_payload(data: bytes, content_type: str) -> List[Dict[str, Any]]:
    """Decode LLMObs payload (gzip+msgpack or JSON)."""
    events: List[Dict[str, Any]] = []
    try:
        if content_type and "gzip" in content_type.lower():
            data = gzip.decompress(data)

        if content_type and "msgpack" in content_type.lower():
            payload = msgpack.unpackb(data, raw=False, strict_map_key=False)
        else:
            try:
                payload = json.loads(data)
            except json.JSONDecodeError:
                payload = msgpack.unpackb(data, raw=False, strict_map_key=False)

        if isinstance(payload, list):
            events.extend(payload)
        else:
            events.append(payload)
    except Exception as e:
        log.warning(f"Failed to decode LLMObs payload: {e}")
    return events


def extract_fields_from_tags(tags: List[str]) -> Dict[str, str]:
    """Extract ml_app, service, env, session_id, etc. from tags array."""
    result: Dict[str, str] = {}
    fields_to_extract = ["ml_app", "service", "env", "version", "source", "language", "session_id", "hostname"]
    for tag in tags:
        if not isinstance(tag, str) or ":" not in tag:
            continue
        key, value = tag.split(":", 1)
        if key in fields_to_extract:
            result[key] = value
    return result


def remap_sdk_span_to_ui_format(span: Dict[str, Any], event_ml_app: str = "") -> Dict[str, Any]:
    """Remap span from SDK format to UI-expected format (extract ml_app, service, env, session_id from tags)."""
    tags = span.get("tags", [])
    extracted = extract_fields_from_tags(tags)

    ml_app = extracted.get("ml_app") or event_ml_app or span.get("ml_app") or "lapdog"
    span["ml_app"] = ml_app

    if "service" not in span or not span["service"]:
        span["service"] = extracted.get("service", "")
    if "env" not in span or not span["env"]:
        span["env"] = extracted.get("env", "")

    if "session_id" not in span or not span["session_id"]:
        span["session_id"] = extracted.get("session_id", "")

    if "hostname" not in span or not span["hostname"]:
        span["hostname"] = extracted.get("hostname", "")

    meta = span.get("meta", {})
    span_kind = meta.get("span", {}).get("kind", "llm")

    if "meta" not in span:
        span["meta"] = {}
    if "span" not in span["meta"]:
        span["meta"]["span"] = {}
    span["meta"]["span"]["kind"] = span_kind
    span["_ui_kind"] = span_kind
    span["_ui_ml_app"] = ml_app

    return span


def extract_spans_from_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract individual spans from LLMObs event payloads."""
    spans: List[Dict[str, Any]] = []
    for event in events:
        event_ml_app = event.get("ml_app", "")
        event_tags = event.get("tags", [])

        for span in event.get("spans", []):
            span_tags = span.get("tags", [])
            if event_tags:
                span_tags = list(set(span_tags + event_tags))
            span["tags"] = span_tags
            spans.append(remap_sdk_span_to_ui_format(span, event_ml_app))
    return spans


def llmobs_evp_dedup_keys_from_payload(body_bytes: bytes, content_type: str) -> Set[Tuple[Any, Any]]:
    """Return ``(trace_id, span_id)`` keys from a real ``/evp_proxy/.../llmobs`` request body."""
    keys: Set[Tuple[Any, Any]] = set()
    try:
        for event in decode_llmobs_payload(body_bytes, content_type):
            for span in event.get("spans", []) or []:
                keys.add((span.get("trace_id"), span.get("span_id")))
    except Exception as exc:
        log.debug("Failed to decode real EVP llmobs payload for dedup: %s", exc)
    return keys
