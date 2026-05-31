"""Stdio MCP server for querying traces captured by a running lapdog agent.

This is a thin client: it speaks the MCP protocol over stdio to the calling agent
(Claude Code, Claude Desktop, ...) and fetches span data over HTTP from the lapdog
agent already running on localhost (started by `lapdog start` / `lapdog claude`).

It reuses the same query endpoints the lapdog dashboard uses, so span assembly,
session_id normalization, and filter parsing all happen server-side in the agent.

Run with: lapdog mcp
"""

import functools
import os
import sys
from typing import Any
from typing import Callable
from typing import Dict
from typing import List

import requests

from lapdog.cli import _read_pid_file

# The agent endpoint that returns assembled, normalized LLMObs spans. Each event
# carries the span under event["event"]["custom"]. Filtering (e.g. "error:true",
# "ml_app:foo") is applied server-side via the agent's parse_filter_query.
_LIST_PATH = "/api/unstable/llm-obs-query-rewriter/list?type=llmobs"

# Upper bound when we need "all" spans for grouping/tree assembly. The agent stores
# spans in memory for a single local session, so this is comfortably large.
_MAX_SPANS = 5000

_HTTP_TIMEOUT = 10.0


class AgentUnavailable(Exception):
    """Raised when the lapdog agent cannot be reached over HTTP."""


def _agent_base_url() -> str:
    """Return the base URL of the running lapdog agent.

    Discovers the port from the lapdog pid file (~/.lapdog/lapdog.pid), falling
    back to the PORT env var, then 8126.
    """
    _, port = _read_pid_file()
    if port is None:
        port = int(os.environ.get("PORT", "8126"))
    return f"http://127.0.0.1:{port}"


def _post_list(query: str, limit: int) -> List[Dict[str, Any]]:
    """POST to the agent's list endpoint and return the raw span dicts (custom objects).

    Raises AgentUnavailable with an actionable message if the agent is down.
    """
    url = f"{_agent_base_url()}{_LIST_PATH}"
    body = {"list": {"limit": limit, "search": {"query": query}}}
    try:
        resp = requests.post(url, json=body, timeout=_HTTP_TIMEOUT)
        resp.raise_for_status()
    except requests.RequestException as e:
        raise AgentUnavailable(
            "Could not reach the lapdog agent at "
            f"{_agent_base_url()} ({e}). Start it with `lapdog start` "
            "(or `lapdog claude` / `lapdog codex`) and try again."
        ) from e

    data = resp.json()
    events = data.get("result", {}).get("events", [])
    spans: List[Dict[str, Any]] = []
    for event in events:
        custom = event.get("event", {}).get("custom")
        if isinstance(custom, dict):
            spans.append(custom)
    return spans


def _span_metrics(span: Dict[str, Any]) -> Dict[str, Any]:
    metrics = span.get("metrics", {}) or {}
    return {
        "input_tokens": metrics.get("input_tokens", 0),
        "output_tokens": metrics.get("output_tokens", 0),
        "total_tokens": metrics.get("total_tokens", 0),
        "estimated_total_cost": metrics.get("estimated_total_cost", 0),
    }


def _truncate(value: Any, limit: int = 500) -> Any:
    """Truncate long string values so previews stay small in tool output."""
    if isinstance(value, str) and len(value) > limit:
        return value[:limit] + "…"
    return value


def _span_summary(span: Dict[str, Any]) -> Dict[str, Any]:
    """Compact span representation for search results."""
    meta = span.get("meta", {}) or {}
    return {
        "span_id": span.get("span_id", ""),
        "trace_id": span.get("trace_id", ""),
        "session_id": span.get("session_id", ""),
        "name": span.get("name", ""),
        "ml_app": span.get("ml_app", ""),
        "status": span.get("status", "ok"),
        "duration_ns": span.get("duration", 0),
        "start_ns": span.get("start_ns", 0),
        "metrics": _span_metrics(span),
        "input": _truncate(meta.get("input")),
        "output": _truncate(meta.get("output")),
    }


def list_sessions(limit: int = 50) -> Dict[str, Any]:
    """List captured coding/LLM sessions with roll-up stats.

    Returns up to `limit` sessions, most recent first. Each session aggregates its
    spans: span count, error count, total tokens, estimated total cost, and time range.
    """
    spans = _post_list("", _MAX_SPANS)

    sessions: Dict[str, Dict[str, Any]] = {}
    order: List[str] = []
    for span in spans:
        sid = span.get("session_id") or "(no session)"
        if sid not in sessions:
            sessions[sid] = {
                "session_id": sid,
                "ml_app": span.get("ml_app", ""),
                "span_count": 0,
                "error_count": 0,
                "total_tokens": 0,
                "estimated_total_cost": 0.0,
                "start_ns": None,
                "end_ns": None,
            }
            order.append(sid)
        agg = sessions[sid]
        agg["span_count"] += 1
        if span.get("status") == "error":
            agg["error_count"] += 1
        m = _span_metrics(span)
        agg["total_tokens"] += m["total_tokens"] or 0
        try:
            agg["estimated_total_cost"] += float(m["estimated_total_cost"] or 0)
        except (TypeError, ValueError):
            pass
        start_ns = span.get("start_ns")
        if isinstance(start_ns, (int, float)):
            end_ns = start_ns + (span.get("duration", 0) or 0)
            if agg["start_ns"] is None or start_ns < agg["start_ns"]:
                agg["start_ns"] = start_ns
            if agg["end_ns"] is None or end_ns > agg["end_ns"]:
                agg["end_ns"] = end_ns

    # spans come back sorted desc by start_ns, so `order` is already most-recent-first.
    result = [sessions[sid] for sid in order[:limit]]
    return {"session_count": len(result), "sessions": result}


def search_spans(query: str, limit: int = 50) -> Dict[str, Any]:
    """Search spans using the lapdog agent's Datadog-style filter syntax.

    Attributes use an `@` prefix; tags do not. Supports AND/OR/NOT and wildcards.
    `query` examples: "@status:error", "@ml_app:my-app", "@meta.model_name:claude*",
    "session_id:abc123". An empty query returns the most recent spans. Returns
    compact span summaries.
    """
    spans = _post_list(query, limit)
    return {"span_count": len(spans), "spans": [_span_summary(s) for s in spans]}


def get_session(session_id: str) -> Dict[str, Any]:
    """Fetch all spans for one session, assembled into parent/child trees.

    Returns the root spans for the session, each with nested `children`, including
    input/output and metrics per span.
    """
    spans = _post_list(f"session_id:{session_id}", _MAX_SPANS)
    if not spans:
        return {"session_id": session_id, "span_count": 0, "roots": []}

    by_id: Dict[str, Dict[str, Any]] = {}
    for span in spans:
        node = _span_summary(span)
        node["children"] = []
        by_id[span.get("span_id", "")] = node

    roots: List[Dict[str, Any]] = []
    for span in spans:
        node = by_id[span.get("span_id", "")]
        parent_id = span.get("parent_id")
        if parent_id and parent_id not in ("undefined", "0", "") and parent_id in by_id:
            by_id[parent_id]["children"].append(node)
        else:
            roots.append(node)

    # Order siblings chronologically (ascending start) for readability.
    def _sort(nodes: List[Dict[str, Any]]) -> None:
        nodes.sort(key=lambda n: n.get("start_ns", 0))
        for n in nodes:
            _sort(n["children"])

    _sort(roots)
    return {"session_id": session_id, "span_count": len(spans), "roots": roots}


def build_server() -> Any:
    """Construct and return the FastMCP server with tools registered."""
    from mcp.server.fastmcp import FastMCP
    from mcp.server.fastmcp.exceptions import ToolError

    mcp = FastMCP("lapdog")

    def _guard(fn: Callable[..., Any]) -> Callable[..., Any]:
        """Translate AgentUnavailable into a clean MCP ToolError for the client.

        functools.wraps preserves the wrapped function's signature (via
        __wrapped__) so FastMCP can introspect the tool's parameters/annotations.
        """

        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                return fn(*args, **kwargs)
            except AgentUnavailable as e:
                raise ToolError(str(e)) from e

        return wrapper

    mcp.tool()(_guard(list_sessions))
    mcp.tool()(_guard(search_spans))
    mcp.tool()(_guard(get_session))
    return mcp


def run() -> None:
    """Run the stdio MCP server (blocks until the client disconnects)."""
    if not _agent_reachable():
        print(
            "[lapdog] Warning: lapdog agent not reachable; start it with `lapdog start` "
            "or `lapdog claude`. Serving MCP anyway; tool calls will report the agent is down.",
            file=sys.stderr,
        )
    build_server().run(transport="stdio")


def _agent_reachable() -> bool:
    try:
        requests.get(f"{_agent_base_url()}/info", timeout=2).raise_for_status()
        return True
    except requests.RequestException:
        return False
