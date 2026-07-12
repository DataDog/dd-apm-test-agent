"""Forward decoded tracer payloads to the agentless JSON trace intake."""

import json
import logging
from typing import Any
from typing import Dict
from typing import Mapping
from typing import Optional

from aiohttp import ClientSession
from aiohttp import ClientTimeout

from .trace import Span
from .trace import Trace
from .trace import v04TracePayload

log = logging.getLogger(__name__)


TRACE_INTAKE_URLS = {
    "datadoghq.com": "https://public-trace-http-intake.logs.datadoghq.com/api/v2/spans",
    "datadoghq.eu": "https://public-trace-http-intake.logs.datadoghq.eu/api/v2/spans",
    "us3.datadoghq.com": "https://trace.browser-intake-us3-datadoghq.com/api/v2/spans",
    "us5.datadoghq.com": "https://trace.browser-intake-us5-datadoghq.com/api/v2/spans",
    "ap1.datadoghq.com": "https://browser-intake-ap1-datadoghq.com/api/v2/spans",
    "ap2.datadoghq.com": "https://browser-intake-ap2-datadoghq.com/api/v2/spans",
    "uk1.datadoghq.com": "https://browser-intake-uk1-datadoghq.com/api/v2/spans",
    "datad0g.com": "https://public-trace-http-intake.logs.datad0g.com/api/v2/spans",
}

_FORWARDED_TRACER_HEADERS = (
    "Datadog-Meta-Lang",
    "Datadog-Meta-Lang-Version",
    "Datadog-Meta-Lang-Interpreter",
    "Datadog-Meta-Tracer-Version",
)

_V2_SPAN_FIELDS = (
    "service",
    "resource",
    "name",
    "type",
    "start",
    "duration",
    "error",
    "meta_struct",
)


def trace_intake_url(site: str) -> str:
    """Return the agentless JSON trace intake URL for a Datadog site."""
    normalized_site = site.lower()
    known_url = TRACE_INTAKE_URLS.get(normalized_site)
    if known_url is not None:
        return known_url

    prefix, separator, tld = normalized_site.rpartition(".")
    if not separator:
        raise ValueError(f"Invalid Datadog site: {site!r}")
    return f"https://browser-intake-{prefix.replace('.', '-')}.{tld}/api/v2/spans"


def _hex_id(value: Optional[int]) -> str:
    return f"{(value or 0) & 0xFFFFFFFFFFFFFFFF:016x}"


def _trace_id(span: Span) -> str:
    low = _hex_id(span["trace_id"])
    high = str((span.get("meta") or {}).get("_dd.p.tid", ""))
    if len(high) == 16:
        try:
            int(high, 16)
        except ValueError:
            pass
        else:
            return high.lower() + low
    return low


def _is_top_level(span: Span, spans_by_id: Mapping[int, Span]) -> bool:
    parent_id = span.get("parent_id") or 0
    if parent_id == 0:
        return True
    parent = spans_by_id.get(parent_id)
    return parent is None or parent.get("service") != span.get("service")


def _span_to_v2(
    span: Span,
    spans_by_id: Mapping[int, Span],
    compute_stats: bool,
    forwarding_tags: Mapping[str, str],
) -> Dict[str, Any]:
    span_values: Mapping[str, Any] = span
    forwarded = {
        key: span_values[key] for key in _V2_SPAN_FIELDS if key in span_values and span_values[key] is not None
    }
    forwarded["trace_id"] = _trace_id(span)
    forwarded["parent_id"] = _hex_id(span.get("parent_id"))
    forwarded["span_id"] = _hex_id(span["span_id"])

    meta = dict(span.get("meta") or {})
    meta.update(forwarding_tags)
    metrics = dict(span.get("metrics") or {})
    if compute_stats:
        meta["_dd.compute_stats"] = "1"
    if not (span.get("parent_id") or 0):
        metrics["_trace_root"] = 1
    if _is_top_level(span, spans_by_id):
        metrics["_top_level"] = 1

    if meta:
        forwarded["meta"] = meta
    if metrics:
        forwarded["metrics"] = metrics
    return forwarded


def _trace_to_v2(trace: Trace, forwarding_tags: Mapping[str, str]) -> Dict[str, Any]:
    spans_by_id = {span["span_id"]: span for span in trace}
    return {
        "spans": [
            _span_to_v2(span, spans_by_id, compute_stats=index == 0, forwarding_tags=forwarding_tags)
            for index, span in enumerate(trace)
        ]
    }


def build_v2_trace_payload(
    traces: v04TracePayload,
    forwarding_tags: Optional[Mapping[str, str]] = None,
) -> Dict[str, Any]:
    """Build the strict JSON payload accepted by ``/api/v2/spans``.

    Span fields supported by the strict JSON intake schema are preserved except
    for its required hexadecimal ID representation. The same minimal
    stats/root/top-level markers used by the official agentless Python trace
    writer and any configured forwarding tags are added to copied meta/metrics
    maps; the decoded traces themselves are not mutated.
    """
    tags = forwarding_tags or {}
    return {"traces": [_trace_to_v2(trace, tags) for trace in traces if trace]}


async def forward_traces_to_v2_intake(
    traces: v04TracePayload,
    request_headers: Mapping[str, str],
    site: str,
    api_key: str,
    forwarding_tags: Optional[Mapping[str, str]] = None,
) -> bool:
    """Forward traces once to the agentless v2 intake without changing local handling."""
    if not api_key:
        log.error("No DD_API_KEY set to forward traces to the v2 intake. Skipping forwarding.")
        return False

    payload = build_v2_trace_payload(traces, forwarding_tags)
    if not payload["traces"]:
        return True

    url = trace_intake_url(site)
    headers = {
        "Content-Type": "application/json",
        "dd-api-key": api_key,
        **{key: request_headers[key] for key in _FORWARDED_TRACER_HEADERS if key in request_headers},
    }
    async with ClientSession(timeout=ClientTimeout(total=10)) as session:
        async with session.post(url, headers=headers, data=json.dumps(payload).encode("utf-8")) as response:
            if response.status < 200 or response.status >= 300:
                log.warning(
                    "Failed to forward traces to the v2 intake: %s %s",
                    response.status,
                    await response.text(),
                )
                return False
    return True
