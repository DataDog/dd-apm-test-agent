"""Leash API — feedback-loop harness for coding agents.

Leash exposes a small HTTP API that a UI (or a coding agent) can use to
inspect traces for a target application and, eventually, run
llm-as-a-judge evaluations against those traces.

The pilot target is the ``dundercode`` application. For now, the target
app is hardcoded here; future iterations will make this configurable.
"""

import logging
import time
from typing import Any
from typing import Dict
from typing import List
from typing import TYPE_CHECKING

log = logging.getLogger(__name__)


def _time_ns_now() -> int:
    return time.time_ns()

from aiohttp import web
from aiohttp.web import Request

from .llmobs_event_platform import with_cors

if TYPE_CHECKING:
    from .agent import Agent
    from .claude_hooks import ClaudeHooksAPI
    from .claude_hooks import SessionState
    from .llmobs_event_platform import LLMObsEventPlatformAPI


# Hardcoded target app registry for the pilot. Key is the app id used in
# the UI and on the wire; value is UI-facing metadata plus the ml_app /
# service tag to use when filtering spans.
_APPS: Dict[str, Dict[str, Any]] = {
    "dundercode": {
        "id": "dundercode",
        "name": "dundercode",
        "description": "Searchable transcript database for The Office.",
        "repo_path": "~/dev/dundercode",
        "ml_app": "dundercode",
        "service": "dundercode",
        "focus_codepath": "dundercode/data.py::find_lines",
        "focus_description": "Search across transcript lines.",
    },
}


def _llmobs_trace_summary(spans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarise a list of LLMObs spans belonging to the same trace_id."""
    root = next((s for s in spans if not s.get("parent_id") or s.get("parent_id") == "0"), spans[0])
    start_ns = min(s.get("start_ns", 0) for s in spans)
    end_ns = max(s.get("start_ns", 0) + s.get("duration", 0) for s in spans)
    errored = any(s.get("status") == "error" for s in spans)
    kinds = sorted({(s.get("meta") or {}).get("span", {}).get("kind") or "" for s in spans} - {""})
    return {
        "trace_id": str(root.get("trace_id") or ""),
        "root_span_id": str(root.get("span_id") or ""),
        "root_name": root.get("name") or "(unnamed)",
        "root_kind": (root.get("meta") or {}).get("span", {}).get("kind") or "",
        "span_count": len(spans),
        "start_ns": start_ns,
        "duration_ns": max(0, end_ns - start_ns),
        "status": "error" if errored else "ok",
        "service": root.get("service") or "",
        "ml_app": root.get("ml_app") or "",
        "session_id": root.get("session_id") or "",
        "kinds": kinds,
        "source": "llmobs",
    }


def _apm_trace_summary(spans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Summarise a list of APM spans belonging to the same trace_id."""
    root = next(
        (s for s in spans if not s.get("parent_id")),
        min(spans, key=lambda s: s.get("start", 0)),
    )
    start_ns = min(s.get("start", 0) for s in spans)
    end_ns = max(s.get("start", 0) + s.get("duration", 0) for s in spans)
    errored = any(s.get("error") for s in spans)
    types = sorted({s.get("type") or "" for s in spans} - {""})
    return {
        "trace_id": str(root.get("trace_id") or ""),
        "root_span_id": str(root.get("span_id") or ""),
        "root_name": root.get("resource") or root.get("name") or "(unnamed)",
        "root_kind": root.get("type") or root.get("name") or "",
        "span_count": len(spans),
        "start_ns": start_ns,
        "duration_ns": max(0, end_ns - start_ns),
        "status": "error" if errored else "ok",
        "service": root.get("service") or "",
        "ml_app": "",
        "session_id": "",
        "kinds": types,
        "source": "apm",
    }


def _tool_name_from_span(span: Dict[str, Any]) -> str:
    for tag in span.get("tags") or []:
        if isinstance(tag, str) and tag.startswith("tool_name:"):
            return tag[len("tool_name:"):]
    return (span.get("name") or "").split(" - ", 1)[0]


def _estimate_context_window(model: str, peak_input_tokens: int) -> int:
    """Estimate the model's context-window size in tokens.

    We cannot tell from the span alone whether the session is using Anthropic's
    1M-token beta, so we fall back to a heuristic: if we have ever observed an
    input > 200k tokens, the session must be on the 1M tier.
    """
    name = (model or "").lower()
    if peak_input_tokens > 200_000:
        return 1_000_000
    if "opus" in name or "sonnet" in name:
        return 200_000
    return 200_000


def _context_usage_from_llm_spans(llm_spans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compute a compact context-usage summary from the session's LLM spans.

    Uses the latest LLM span as "current" context, and the max across all
    spans as the observed peak.
    """
    if not llm_spans:
        return {
            "current_tokens": 0,
            "peak_tokens": 0,
            "max_tokens": 200_000,
            "pct": 0.0,
            "breakdown": None,
        }
    latest = max(llm_spans, key=lambda s: s.get("start_ns", 0) or 0)
    metrics = latest.get("metrics") or {}
    current = int(metrics.get("input_tokens") or 0)
    peak = max(int((s.get("metrics") or {}).get("input_tokens") or 0) for s in llm_spans)
    model = latest.get("name") or ""
    max_tokens = _estimate_context_window(model, peak)
    pct = (current / max_tokens * 100.0) if max_tokens else 0.0

    cached = int(metrics.get("cache_read_input_tokens") or 0)
    cache_write = int(metrics.get("cache_write_input_tokens") or 0)
    non_cached = int(metrics.get("non_cached_input_tokens") or max(0, current - cached - cache_write))
    output = int(metrics.get("output_tokens") or 0)

    return {
        "current_tokens": current,
        "peak_tokens": peak,
        "max_tokens": max_tokens,
        "pct": round(pct, 2),
        "breakdown": {
            "cached_reused": cached,
            "new_this_turn": non_cached,
            "newly_cached": cache_write,
            "output": output,
        },
    }


def _session_summary(state: "SessionState", spans: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Build a Leash-friendly summary of a Claude Code session.

    Pulls aggregates off the assembled spans (tool counts, permission-wait
    totals, etc.) and combines them with live session state that isn't on
    the spans (the original user prompt, the model).
    """
    tool_spans = [s for s in spans if (s.get("meta") or {}).get("span", {}).get("kind") == "tool"]
    agent_spans = [s for s in spans if (s.get("meta") or {}).get("span", {}).get("kind") == "agent"]
    llm_spans = [s for s in spans if (s.get("meta") or {}).get("span", {}).get("kind") == "llm"]

    # Token + cost aggregates across every LLM span in the session. Costs on
    # individual LLM spans are stored in nanodollars by
    # ``claude_cost_tracker.compute_cost_metrics``.
    token_totals = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_write_input_tokens": 0,
        "non_cached_input_tokens": 0,
        "total_tokens": 0,
    }
    cost_nano = {
        "estimated_input_cost": 0,
        "estimated_output_cost": 0,
        "estimated_cache_read_input_cost": 0,
        "estimated_cache_write_input_cost": 0,
        "estimated_non_cached_input_cost": 0,
        "estimated_total_cost": 0,
    }
    models_used: Dict[str, Dict[str, int]] = {}
    for span in llm_spans:
        metrics = span.get("metrics") or {}
        for k in token_totals:
            token_totals[k] += int(metrics.get(k) or 0)
        for k in cost_nano:
            cost_nano[k] += int(metrics.get(k) or 0)
        model = span.get("name") or ""
        if model:
            mt = models_used.setdefault(
                model, {"calls": 0, "total_tokens": 0, "estimated_total_cost": 0}
            )
            mt["calls"] += 1
            mt["total_tokens"] += int(metrics.get("total_tokens") or 0)
            mt["estimated_total_cost"] += int(metrics.get("estimated_total_cost") or 0)
    cost_usd = {k: v / 1_000_000_000 for k, v in cost_nano.items()}
    # Claude pricing discounts cache-read tokens ~10x vs non-cached input
    # across Opus/Sonnet/Haiku, so the counterfactual "what would we have
    # spent without caching" is ~10x the cache-read cost. Savings = 9x.
    cost_usd["cache_savings"] = cost_usd["estimated_cache_read_input_cost"] * 9
    models_breakdown = [
        {
            "model": model,
            "calls": info["calls"],
            "total_tokens": info["total_tokens"],
            "estimated_total_cost_usd": info["estimated_total_cost"] / 1_000_000_000,
        }
        for model, info in sorted(
            models_used.items(), key=lambda kv: kv[1]["estimated_total_cost"], reverse=True
        )
    ]

    tool_counts: Dict[str, int] = {}
    for s in tool_spans:
        tool_counts[_tool_name_from_span(s)] = tool_counts.get(_tool_name_from_span(s), 0) + 1

    # Aggregate permission-approval friction. Each tool span that required
    # user approval has an estimated_permission_wait_ms under _dd metadata.
    gated_by_name: Dict[str, Dict[str, Any]] = {}
    total_wait_ms = 0
    gated_count = 0
    for s in tool_spans:
        dd = (s.get("meta") or {}).get("metadata", {}).get("_dd", {})
        wait = dd.get("estimated_permission_wait_ms") or 0
        if wait <= 0:
            continue
        gated_count += 1
        total_wait_ms += wait
        key = s.get("name") or _tool_name_from_span(s)
        entry = gated_by_name.setdefault(
            key,
            {"name": key, "tool_name": _tool_name_from_span(s), "count": 0, "wait_ms": 0},
        )
        entry["count"] += 1
        entry["wait_ms"] += wait
    by_tool = sorted(gated_by_name.values(), key=lambda x: x["wait_ms"], reverse=True)[:5]

    if spans:
        start_ns = min(s.get("start_ns", state.start_ns) for s in spans)
        end_ns = max(s.get("start_ns", 0) + s.get("duration", 0) for s in spans)
        duration_ns = max(0, end_ns - start_ns)
    else:
        start_ns = state.start_ns
        duration_ns = 0

    # Status: blocked > running > idle. "blocked" means the session is
    # waiting on a user permission prompt; "running" means tools are
    # in-flight or the root span hasn't been emitted (still in a turn);
    # otherwise the session is idle.
    if state.pending_permission_at_ns is not None:
        status = "blocked"
    elif state.pending_tools or not state.root_span_emitted:
        status = "running"
    else:
        status = "idle"

    return {
        "session_id": state.session_id,
        "trace_id": str(state.trace_id or ""),
        "started_ns": start_ns,
        "duration_ns": duration_ns,
        "model": state.model,
        "status": status,
        "first_prompt": state.user_prompts[0] if state.user_prompts else "",
        "current_task": state.user_prompts[-1] if state.user_prompts else "",
        "current_task_started_ns": state.current_task_started_ns,
        "prompt_count": len(state.user_prompts),
        "tool_call_count": len(tool_spans),
        "tool_counts": tool_counts,
        "agent_span_count": len(agent_spans),
        "llm_span_count": len(llm_spans),
        "tokens": token_totals,
        "cost_usd": cost_usd,
        "models": models_breakdown,
        "context": _context_usage_from_llm_spans(llm_spans),
        "permission": {
            "total_wait_ms": total_wait_ms,
            "gated_call_count": gated_count,
            "by_tool": by_tool,
        },
        "in_progress": any((s.get("duration") or 0) < 0 for s in spans) or not state.root_span_emitted,
    }


class LeashAPI:
    """HTTP API backing the Leash UI."""

    def __init__(
        self,
        agent: "Agent",
        llmobs_api: "LLMObsEventPlatformAPI",
        claude_hooks_api: "ClaudeHooksAPI",
    ) -> None:
        self._agent = agent
        self._llmobs_api = llmobs_api
        self._claude_hooks_api = claude_hooks_api
        # session_id → {"prompt": str, "status": "pending"|"done"|"error",
        #               "summary": Optional[str], "error": Optional[str]}
        self._task_summaries: Dict[str, Dict[str, Any]] = {}

    def _get_or_schedule_task_summary(
        self, session_id: str, current_prompt: str
    ) -> Dict[str, Any]:
        """Return the cached summary entry for *session_id*.

        Currently **disabled**: calling ``claude-code-sdk`` from inside the
        test agent spawns a new Claude Code CLI subprocess whose hooks also
        report back to this agent, producing a fresh session that itself
        gets summarised, ad infinitum. Needs a summariser that does not go
        through the Claude Code CLI (e.g. the ``anthropic`` SDK directly)
        or a tag that lets us skip self-originated sessions. See LEASH_TODO.
        Until then, always report idle so the UI falls back to the raw
        prompt preview.
        """
        return {"status": "idle", "summary": None}

    async def _compute_task_summary(self, session_id: str, prompt: str) -> None:
        """Disabled — see _get_or_schedule_task_summary for the reason."""
        result = await _summarise_task(prompt)
        existing = self._task_summaries.get(session_id)
        if existing is None or existing.get("prompt") != prompt:
            return
        self._task_summaries[session_id] = {
            "prompt": prompt,
            "status": result.get("status", "error"),
            "summary": result.get("summary"),
            "error": result.get("error"),
        }

    def _llmobs_spans_for_app(self, app: Dict[str, Any]) -> List[Dict[str, Any]]:
        ml_app = app["ml_app"]
        service = app["service"]
        return [
            s for s in self._llmobs_api.get_llmobs_spans()
            if s.get("ml_app") == ml_app or s.get("service") == service
        ]

    async def _apm_traces_for_app(self, app: Dict[str, Any]) -> List[List[Dict[str, Any]]]:
        service = app["service"]
        trace_map = await self._agent.traces()
        out: List[List[Dict[str, Any]]] = []
        for spans in trace_map.values():
            if any(s.get("service") == service for s in spans):
                out.append(list(spans))
        return out

    async def handle_list_apps(self, request: Request) -> web.Response:
        return web.json_response({"apps": list(_APPS.values())})

    async def handle_get_app(self, request: Request) -> web.Response:
        app_id = request.match_info["app_id"]
        app = _APPS.get(app_id)
        if app is None:
            return web.json_response({"error": f"unknown app: {app_id}"}, status=404)
        llmobs_spans = self._llmobs_spans_for_app(app)
        apm_traces = await self._apm_traces_for_app(app)
        llmobs_trace_ids = {s.get("trace_id") for s in llmobs_spans if s.get("trace_id")}
        apm_span_count = sum(len(t) for t in apm_traces)
        return web.json_response({
            **app,
            "trace_count": len(llmobs_trace_ids) + len(apm_traces),
            "span_count": len(llmobs_spans) + apm_span_count,
        })

    async def handle_list_traces(self, request: Request) -> web.Response:
        app_id = request.query.get("app", "dundercode")
        limit = int(request.query.get("limit", "50"))
        app = _APPS.get(app_id)
        if app is None:
            return web.json_response({"error": f"unknown app: {app_id}"}, status=404)

        summaries: List[Dict[str, Any]] = []

        llmobs_spans = self._llmobs_spans_for_app(app)
        by_trace: Dict[str, List[Dict[str, Any]]] = {}
        for s in llmobs_spans:
            tid = s.get("trace_id")
            if tid:
                by_trace.setdefault(tid, []).append(s)
        summaries.extend(_llmobs_trace_summary(g) for g in by_trace.values())

        for group in await self._apm_traces_for_app(app):
            summaries.append(_apm_trace_summary(group))

        summaries.sort(key=lambda t: t.get("start_ns", 0), reverse=True)
        return web.json_response({"app": app_id, "traces": summaries[:limit], "total": len(summaries)})

    async def handle_get_trace(self, request: Request) -> web.Response:
        """Return all spans for a given trace.

        Supports both APM traces (source=apm) and LLMObs spans (source=llmobs).
        Useful for the UI to introspect a trace's full span tree.
        """
        trace_id = request.match_info["trace_id"]
        source = request.query.get("source", "apm")

        if source == "llmobs":
            spans = [
                s for s in self._llmobs_api.get_llmobs_spans()
                if str(s.get("trace_id") or "") == trace_id
            ]
            return web.json_response({"source": "llmobs", "trace_id": trace_id, "spans": spans})

        trace_map = await self._agent.traces()
        apm_spans: List[Dict[str, Any]] = []
        for tid, group in trace_map.items():
            if str(tid) == trace_id:
                apm_spans = list(group)
                break
        return web.json_response({"source": "apm", "trace_id": trace_id, "spans": apm_spans})

    async def handle_app_metrics(self, request: Request) -> web.Response:
        """Derived application metrics for the target app.

        Until OTLP metrics flow from the app, we compute KPIs directly from
        the APM traces stored by the test agent. This keeps the dashboard
        useful for any app that already emits APM.
        """
        app_id = request.query.get("app", "dundercode")
        window_s = int(request.query.get("window_s", "300"))
        app = _APPS.get(app_id)
        if app is None:
            return web.json_response({"error": f"unknown app: {app_id}"}, status=404)

        groups = await self._apm_traces_for_app(app)
        service = app["service"]

        root_spans: List[Dict[str, Any]] = []
        for spans in groups:
            root = next(
                (s for s in spans if not s.get("parent_id") and s.get("service") == service),
                None,
            )
            if root is not None:
                root_spans.append(root)

        now_ns = _time_ns_now()
        window_ns = window_s * 1_000_000_000
        recent = [s for s in root_spans if s.get("start", 0) >= now_ns - window_ns]

        def _pct(xs: List[int], q: float) -> int:
            if not xs:
                return 0
            xs = sorted(xs)
            i = min(len(xs) - 1, max(0, int(round(q * (len(xs) - 1)))))
            return xs[i]

        durations = [int(s.get("duration") or 0) for s in recent]
        err_count = sum(1 for s in recent if s.get("error"))

        by_resource: Dict[str, Dict[str, Any]] = {}
        for s in recent:
            key = s.get("resource") or s.get("name") or ""
            entry = by_resource.setdefault(key, {"resource": key, "count": 0, "errors": 0, "total_duration_ns": 0})
            entry["count"] += 1
            if s.get("error"):
                entry["errors"] += 1
            entry["total_duration_ns"] += int(s.get("duration") or 0)
        top = sorted(by_resource.values(), key=lambda r: r["count"], reverse=True)[:8]

        bucket_count = 30
        bucket_ns = window_ns // bucket_count if bucket_count else window_ns
        buckets = [{"t_ns": now_ns - window_ns + i * bucket_ns, "count": 0, "errors": 0} for i in range(bucket_count)]
        for s in recent:
            idx = int((s.get("start", now_ns) - (now_ns - window_ns)) / bucket_ns) if bucket_ns else 0
            idx = max(0, min(bucket_count - 1, idx))
            buckets[idx]["count"] += 1
            if s.get("error"):
                buckets[idx]["errors"] += 1

        return web.json_response(
            {
                "app": app_id,
                "window_s": window_s,
                "req_count": len(recent),
                "err_count": err_count,
                "error_rate": (err_count / len(recent)) if recent else 0,
                "rps": len(recent) / window_s if window_s else 0,
                "p50_ns": _pct(durations, 0.50),
                "p95_ns": _pct(durations, 0.95),
                "p99_ns": _pct(durations, 0.99),
                "top_endpoints": top,
                "timeseries": buckets,
                "source": "derived_from_apm",
            }
        )

    async def handle_list_sessions(self, request: Request) -> web.Response:
        """List coding-agent (Claude Code) sessions for an app.

        Pilot assumption: every Claude Code session belongs to the currently
        selected app. We don't filter by ml_app for now.
        """
        app_id = request.query.get("app", "dundercode")
        if app_id not in _APPS:
            return web.json_response({"error": f"unknown app: {app_id}"}, status=404)

        sessions_state = self._claude_hooks_api._sessions
        all_spans = self._claude_hooks_api._assembled_spans
        spans_by_session: Dict[str, List[Dict[str, Any]]] = {}
        for s in all_spans:
            sid = s.get("session_id")
            if sid:
                spans_by_session.setdefault(sid, []).append(s)

        sessions: List[Dict[str, Any]] = []
        for sid, state in sessions_state.items():
            summary = _session_summary(state, spans_by_session.get(sid, []))
            current_prompt = state.user_prompts[-1] if state.user_prompts else ""
            task = self._get_or_schedule_task_summary(sid, current_prompt)
            summary["current_task_summary"] = task.get("summary")
            summary["current_task_summary_status"] = task.get("status")
            sessions.append(summary)
        sessions.sort(key=lambda s: s.get("started_ns", 0), reverse=True)
        return web.json_response({"app": app_id, "sessions": sessions})

    def get_routes(self) -> List[web.RouteDef]:
        return [
            web.route("*", "/leash/api/apps", with_cors(self.handle_list_apps)),
            web.route("*", "/leash/api/apps/{app_id}", with_cors(self.handle_get_app)),
            web.route("*", "/leash/api/traces", with_cors(self.handle_list_traces)),
            web.route("*", "/leash/api/sessions", with_cors(self.handle_list_sessions)),
            web.route("*", "/leash/api/app_metrics", with_cors(self.handle_app_metrics)),
            web.route("*", "/leash/api/trace/{trace_id}", with_cors(self.handle_get_trace)),
        ]


def get_app_registry() -> Dict[str, Dict[str, Any]]:
    return _APPS


# ---------------------------------------------------------------------------
# Task summarisation (LLM-assisted, cached per session)
# ---------------------------------------------------------------------------

_TASK_SUMMARY_SYSTEM_PROMPT = """\
You summarise a single user prompt to a coding agent into a concise task \
label that can fit in a small status row.

Rules:
- <= 8 words.
- Imperative voice, e.g. "Improve dundercode search" or "Fix Slack unfurl".
- No quotes, no trailing punctuation, plain text only.
- Prefer verbs that describe the concrete outcome, not the process \
  ("Add eval button" beats "Help me add a button").
- If the prompt is a continuation or meta-request ("resume", "sounds good", \
  "ok commit"), emit just the word "continue" or "commit" accordingly.

Output ONLY the summary line. No preamble. No trailing newline content.
"""

_TASK_SUMMARY_MODEL = "claude-haiku-4-5-20251001"
_TASK_SUMMARY_MAX_SUMMARY_LEN = 80


async def _summarise_task(prompt: str) -> Dict[str, Any]:
    """Call haiku via claude-code-sdk to summarise *prompt* into a task label."""
    try:
        from claude_code_sdk import query as claude_query  # type: ignore
        from claude_code_sdk import ClaudeCodeOptions  # type: ignore
        from claude_code_sdk import AssistantMessage  # type: ignore
    except ImportError:
        return {"status": "error", "summary": None, "error": "claude-code-sdk is not installed"}

    options = ClaudeCodeOptions(
        system_prompt=_TASK_SUMMARY_SYSTEM_PROMPT,
        model=_TASK_SUMMARY_MODEL,
        max_turns=1,
    )
    raw = ""
    try:
        async for message in claude_query(prompt=prompt, options=options):
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if hasattr(block, "text"):
                        raw += block.text
    except Exception as e:
        log.warning("task summarisation failed: %s", e)
        return {"status": "error", "summary": None, "error": str(e)}

    summary = raw.strip().strip('"').strip("'").splitlines()[0].strip() if raw.strip() else ""
    if len(summary) > _TASK_SUMMARY_MAX_SUMMARY_LEN:
        summary = summary[: _TASK_SUMMARY_MAX_SUMMARY_LEN - 1] + "…"
    if not summary:
        return {"status": "error", "summary": None, "error": "empty summary"}
    return {"status": "done", "summary": summary, "error": None}
