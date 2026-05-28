"""LLMObs trace meta_struct extraction and session request bridging.

When dd-trace-py ships LLMObs via ``meta_struct["_llmobs"]`` on v0.4 traces instead of
POSTing to ``/evp_proxy/.../llmobs``, helpers here rebuild SDK span events and synthesize
EVP-shaped ``/test/session/requests`` entries (same role as ``traces_otlp.decode_*`` for OTLP).
"""

import base64
import json
import logging
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from aiohttp.web import Request

from .llmobs_payload import remap_sdk_span_to_ui_format


log = logging.getLogger(__name__)

LLMOBS_STRUCT_KEY = "_llmobs"
LLMOBS_ROOT_PARENT_ID = "undefined"

DecodeV04Traces = Callable[[Request], Any]


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


def extract_ui_spans_from_v04_traces(traces: Any) -> List[Dict[str, Any]]:
    """Extract UI-formatted LLMObs spans from decoded v0.4 trace payloads."""
    return [
        remap_sdk_span_to_ui_format(dict(span))
        for envelope in extract_llmobs_envelopes_from_v04_traces(traces)
        for span in envelope.get("spans", [])
    ]


def synthetic_llmobs_session_request_entries(
    envelopes: List[Dict[str, Any]],
    base_url: str,
) -> List[Dict[str, Any]]:
    """Wrap envelopes as ``handle_session_requests``-shaped entries (base64 JSON body)."""
    url = f"{(base_url or '').rstrip('/')}/evp_proxy/v4/api/v2/llmobs"
    return [
        {
            "headers": {
                "Content-Type": "application/json",
                "X-Datadog-EVP-Subdomain": "llmobs-intake",
            },
            "body": base64.b64encode(json.dumps(envelope).encode("utf-8")).decode("ascii"),
            "url": url,
            "method": "POST",
        }
        for envelope in envelopes
    ]


def collect_synthetic_llmobs_session_requests(
    session_reqs: Iterable[Request],
    *,
    decode_v04_traces: DecodeV04Traces,
    is_v04_trace_request: Callable[[Request], bool],
    real_llmobs_evp_keys: Set[Tuple[Any, Any]],
    base_url: str,
) -> List[Dict[str, Any]]:
    """Synthesize ``/evp_proxy/v4/api/v2/llmobs`` session entries from v0.4 ``meta_struct`` spans."""
    synthetic_envelopes: List[Dict[str, Any]] = []
    for req in session_reqs:
        if not is_v04_trace_request(req):
            continue
        try:
            traces = decode_v04_traces(req)
        except Exception as exc:
            log.debug("Failed to decode v0.4 traces for llmobs extract: %s", exc)
            continue
        for envelope in extract_llmobs_envelopes_from_v04_traces(traces):
            event = envelope["spans"][0]
            if (event.get("trace_id"), event.get("span_id")) in real_llmobs_evp_keys:
                continue
            synthetic_envelopes.append(envelope)
    if not synthetic_envelopes:
        return []
    return synthetic_llmobs_session_request_entries(synthetic_envelopes, base_url)
