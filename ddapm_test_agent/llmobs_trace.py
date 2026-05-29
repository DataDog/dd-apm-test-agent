"""LLMObs trace meta_struct extraction.

When dd-trace-py ships LLMObs via ``meta_struct["_llmobs"]`` on v0.4 traces instead of
POSTing to ``/evp_proxy/.../llmobs``, these helpers rebuild SDK span events and writer
envelopes so the agent can synthesize an equivalent EVP request at ingestion time.
"""

import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional


log = logging.getLogger(__name__)

LLMOBS_STRUCT_KEY = "_llmobs"
LLMOBS_ROOT_PARENT_ID = "undefined"


def _llmobs_tags_to_list(tags: Any) -> List[str]:
    if isinstance(tags, dict):
        return sorted(f"{k}:{v}" for k, v in tags.items())
    if isinstance(tags, list):
        return [t for t in tags if isinstance(t, str)]
    return []


def build_sdk_span_event(llmobs_data: Dict[str, Any], span: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Rebuild an SDK span event from ``meta_struct['_llmobs']`` + its host APM span."""
    if not isinstance(llmobs_data, dict) or not isinstance(span, dict):
        return None

    llmobs_trace_id = llmobs_data.get("trace_id")
    apm_span_id = span.get("span_id")
    apm_trace_id = span.get("trace_id")
    if llmobs_trace_id is None or apm_span_id is None or apm_trace_id is None:
        return None

    _dd_attrs: Dict[str, Any] = dict(llmobs_data.get("_dd") or {})
    try:
        apm_trace_id_hex = format(int(apm_trace_id), "032x")
    except (TypeError, ValueError):
        apm_trace_id_hex = str(apm_trace_id)
    _dd_attrs.setdefault("span_id", str(apm_span_id))
    _dd_attrs.setdefault("trace_id", apm_trace_id_hex)
    _dd_attrs.setdefault("apm_trace_id", apm_trace_id_hex)

    span_event: Dict[str, Any] = {
        "trace_id": llmobs_trace_id,
        "span_id": str(apm_span_id),
        "parent_id": llmobs_data.get("parent_id") or LLMOBS_ROOT_PARENT_ID,
        "name": llmobs_data.get("name") or span.get("name", ""),
        "start_ns": span.get("start", 0),
        "duration": span.get("duration", 0),
        "status": "error" if span.get("error") else "ok",
        "meta": llmobs_data.get("meta") or {},
        "metrics": llmobs_data.get("metrics") or {},
        "tags": _llmobs_tags_to_list(llmobs_data.get("tags")),
        "_dd": _dd_attrs,
    }
    for optional_key in ("session_id", "ml_app", "config", "span_links"):
        value = llmobs_data.get(optional_key)
        if value:
            span_event[optional_key] = value
    return span_event


def extract_llmobs_envelopes_from_v04_traces(traces: Any) -> List[Dict[str, Any]]:
    """Build one ``LLMObsSpanWriter._data()``-shaped envelope per LLMObs-bearing span."""
    envelopes: List[Dict[str, Any]] = []
    for trace in traces or []:
        if not isinstance(trace, list):
            continue
        for span in trace:
            if not isinstance(span, dict):
                continue
            meta_struct = span.get("meta_struct") or {}
            if not isinstance(meta_struct, dict):
                continue
            llmobs_data = meta_struct.get(LLMOBS_STRUCT_KEY)
            if not llmobs_data:
                continue
            event = build_sdk_span_event(llmobs_data, span)
            if event is None:
                continue
            envelope: Dict[str, Any] = {
                "_dd.stage": "raw",
                "_dd.tracer_version": "agent-extract",
                "event_type": "span",
                "spans": [event],
            }
            if event.get("_dd", {}).get("scope") == "experiments":
                envelope["_dd.scope"] = "experiments"
            envelopes.append(envelope)
    return envelopes
