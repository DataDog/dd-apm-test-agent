"""Pi Coding Agent Hooks → LLM Observability Spans.

Receives lifecycle events from the pi lapdog extension via HTTP and assembles
them into LLMObs-format spans.  Reuses the ClaudeHooksAPI's session state and
span storage so that pi traces appear alongside Claude Code traces in the UI.

Pi extension events and their mapping:

    session_start     → create session, set model
    agent_start       → start new trace (like UserPromptSubmit)
    agent_end         → finalize root span (like Stop)
    provider_request_context → capture request-side context for next LLM span
    message_start     → begin tracking an LLM span
    message_end       → emit LLM span with token usage
    tool_execution_start → create pending tool span (like PreToolUse)
    tool_execution_end   → emit tool span (like PostToolUse)
    turn_start / turn_end → logged, no span emitted
    model_select      → update session model
    session_compact   → mark compaction on current span
    session_shutdown  → finalize session (like SessionEnd)
"""

import json
import logging
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

from aiohttp import web
from aiohttp.web import Request

from .claude_cost_tracker import compute_cost_metrics
from .claude_cost_tracker import cost_from_provider_usage
from .claude_hooks import ClaudeHooksAPI
from .claude_hooks import PendingToolSpan
from .claude_hooks import SessionState
from .claude_hooks import _ML_APP
from .claude_hooks import _HOSTNAME
from .claude_hooks import _USER_HANDLE
from .claude_hooks import _format_span_id
from .claude_hooks import _format_trace_id
from .claude_hooks import _to_json_str
from .llmobs_event_platform import with_cors


log = logging.getLogger(__name__)


class PendingLLMSpan:
    """Tracks an LLM call between message_start and message_end."""

    def __init__(self, span_id: str, parent_id: str, start_ns: int) -> None:
        self.span_id = span_id
        self.parent_id = parent_id
        self.start_ns = start_ns


class PendingContextBreakdown:
    """Tracks normalized request context captured before a provider request."""

    def __init__(
        self,
        model_id: str,
        model_provider: str,
        context_window_size: int,
        estimated_input_tokens: Optional[int],
        sections: List[Dict[str, Any]],
    ) -> None:
        self.model_id = model_id
        self.model_provider = model_provider
        self.context_window_size = context_window_size
        self.estimated_input_tokens = estimated_input_tokens
        self.sections = sections


class PiHooksAPI:
    """Handler for pi coding agent hook events.

    Delegates to a shared ClaudeHooksAPI for session/span storage and backend
    forwarding so pi traces are queryable through the same Event Platform APIs.
    """

    def __init__(self, hooks_api: ClaudeHooksAPI) -> None:
        self._hooks_api = hooks_api
        self._raw_events: List[Dict[str, Any]] = []
        # Pending LLM span per session (pi sends one LLM call at a time)
        self._pending_llm: Dict[str, PendingLLMSpan] = {}
        self._pending_context: Dict[str, PendingContextBreakdown] = {}

    # ------------------------------------------------------------------
    # Helpers — access shared state via hooks_api
    # ------------------------------------------------------------------

    def _get_or_create_session(self, session_id: str) -> SessionState:
        return self._hooks_api._get_or_create_session(session_id)

    def _current_parent_id(self, session: SessionState) -> str:
        return self._hooks_api._current_parent_id(session)

    def _append_span(self, span: Dict[str, Any]) -> None:
        self._hooks_api._assembled_spans.append(span)

    def _compute_context_breakdown(
        self,
        pending_context: Optional[PendingContextBreakdown],
        total_input_tokens: int,
        fallback_model_id: str,
    ) -> Optional[Dict[str, Any]]:
        if pending_context is None:
            return None

        section_bytes_total = sum(section.get("bytes", 0) for section in pending_context.sections) or 1
        sections: List[Dict[str, Any]] = []
        for section in pending_context.sections:
            section_bytes = section.get("bytes", 0)
            tokens = round(total_input_tokens * section_bytes / section_bytes_total) if total_input_tokens > 0 else 0
            pct = round(tokens / total_input_tokens * 100, 1) if total_input_tokens > 0 else 0.0
            sections.append({"name": section.get("name", "unknown"), "tokens": tokens, "pct": pct})

        context_window_size = pending_context.context_window_size
        context_usage_pct = round(total_input_tokens / context_window_size * 100, 1) if context_window_size > 0 else 0.0

        return {
            "context_window_size": context_window_size,
            "total_input_tokens": total_input_tokens,
            "context_usage_pct": context_usage_pct,
            "sections": sections,
            "model_name": pending_context.model_id or fallback_model_id,
        }

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _handle_session_start(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        model_id = body.get("model_id", "")
        model_provider = body.get("model_provider", "")
        if model_id:
            session.model = model_id
        if model_provider:
            session.model_provider = model_provider
        log.info("Pi session started: %s (model=%s/%s)", session_id, model_provider, model_id)

    def _handle_model_select(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        model_id = body.get("model_id", "")
        model_provider = body.get("model_provider", "")
        if model_id:
            session.model = model_id
        if model_provider:
            session.model_provider = model_provider
        log.info("Pi model changed: %s → %s/%s", session_id, model_provider, model_id)

    def _handle_agent_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Start a new trace for each user turn (equivalent to UserPromptSubmit)."""
        session = self._get_or_create_session(session_id)

        # Finalize previous turn if it wasn't finalized
        if not session.root_span_emitted and getattr(session, "_root_span_ref", None) is not None:
            self._hooks_api._finalize_interrupted_turn(session)

        self._pending_context.pop(session_id, None)

        # Start fresh trace
        if session.root_span_emitted:
            now_ns = int(time.time() * 1_000_000_000)
            session.trace_id = _format_trace_id()
            session.root_span_id = _format_span_id()
            session.start_ns = now_ns
            session.user_prompts = []
            session.tools_used = set()
            session.agent_span_stack = []
            session.pending_tools = {}
            session.deferred_agent_spans = {}
            session.claimed_task_tools = set()
            session.active_agents = {}
            session.root_span_emitted = False

        prompt = body.get("user_prompt", "")
        if prompt:
            session.user_prompts.append(prompt)

        model_id = body.get("model_id", session.model)
        model_provider = body.get("model_provider", session.model_provider)
        if model_id:
            session.model = model_id
        if model_provider:
            session.model_provider = model_provider

        root_span: Dict[str, Any] = {
            "span_id": session.root_span_id,
            "trace_id": session.trace_id,
            "parent_id": "undefined",
            "name": "pi-request",
            "status": "ok",
            "start_ns": session.start_ns,
            "duration": 0,
            "ml_app": _ML_APP,
            "service": _ML_APP,
            "env": "local",
            "session_id": session.session_id,
            "tags": [
                f"ml_app:{_ML_APP}",
                f"session_id:{session.session_id}",
                f"service:{_ML_APP}",
                "env:local",
                "source:pi-hooks",
                "language:python",
                f"hostname:{_HOSTNAME}",
            ]
            + ([f"user_handle:{_USER_HANDLE}"] if _USER_HANDLE else []),
            "meta": {
                "span": {"kind": "agent"},
                "input": {"value": prompt},
                "output": {"value": ""},
                "model_name": model_id,
                "model_provider": model_provider,
            },
            "metrics": {},
        }
        self._append_span(root_span)
        session._root_span_ref = root_span  # type: ignore[attr-defined]

    def _handle_agent_end(self, session_id: str, body: Dict[str, Any]) -> None:
        """Finalize the root span for the current turn (equivalent to Stop)."""
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            log.warning("agent_end for unknown session %s", session_id)
            return

        now_ns = int(time.time() * 1_000_000_000)
        duration = now_ns - session.start_ns
        output_value = body.get("output", "")
        input_value = "\n\n".join(session.user_prompts) if session.user_prompts else ""

        token_usage = self._hooks_api._compute_token_usage(session.trace_id)
        tool_usage = self._hooks_api._aggregate_tool_usage(session.trace_id)
        context_delta = self._hooks_api._compute_context_delta(
            session.trace_id, session.root_span_id, session.last_known_input_tokens
        )
        if context_delta:
            session.last_known_input_tokens = context_delta["last_input_tokens"]

        model_provider = body.get("model_provider", session.model_provider)
        if model_provider:
            session.model_provider = model_provider

        root_span: Optional[Dict[str, Any]] = getattr(session, "_root_span_ref", None)
        if not root_span:
            root_span = next(
                (s for s in self._hooks_api._assembled_spans if s.get("span_id") == session.root_span_id),
                None,
            )

        if root_span:
            root_span["duration"] = duration
            root_span["meta"]["input"]["value"] = input_value
            root_span["meta"]["output"]["value"] = output_value
            root_span["meta"]["model_name"] = session.model
            root_span["meta"]["model_provider"] = model_provider
            root_span["metrics"] = token_usage
            dd_fields: Dict[str, Any] = {}
            if context_delta:
                dd_fields["context_delta"] = context_delta
            if tool_usage:
                dd_fields["tool_usage"] = tool_usage
            dd_fields["agent_manifest"] = {
                "name": _ML_APP,
                "model": session.model,
                "model_provider": model_provider,
                "tools": [{"name": name} for name in sorted(session.tools_used)],
            }
            if dd_fields:
                self._hooks_api._set_hidden_metadata(root_span, **dd_fields)
        else:
            # Fallback: create root span
            root_span = {
                "span_id": session.root_span_id,
                "trace_id": session.trace_id,
                "parent_id": "undefined",
                "name": "pi-request",
                "status": "ok",
                "start_ns": session.start_ns,
                "duration": duration,
                "ml_app": _ML_APP,
                "service": _ML_APP,
                "env": "local",
                "session_id": session.session_id,
                "tags": [
                    f"ml_app:{_ML_APP}",
                    f"session_id:{session.session_id}",
                    f"service:{_ML_APP}",
                    "env:local",
                    "source:pi-hooks",
                    "language:python",
                    f"hostname:{_HOSTNAME}",
                ]
                + ([f"user_handle:{_USER_HANDLE}"] if _USER_HANDLE else []),
                "meta": {
                    "span": {"kind": "agent"},
                    "input": {"value": input_value},
                    "output": {"value": output_value},
                    "model_name": session.model,
                    "model_provider": model_provider,
                },
                "metrics": token_usage,
            }
            if context_delta:
                self._hooks_api._set_hidden_metadata(root_span, context_delta=context_delta)
            self._append_span(root_span)

        session.root_span_emitted = True

    def _handle_provider_request_context(self, session_id: str, body: Dict[str, Any]) -> None:
        """Track normalized request context for the next LLM span."""
        session = self._get_or_create_session(session_id)
        model_id = body.get("model_id", session.model)
        model_provider = body.get("model_provider", session.model_provider)
        if model_id:
            session.model = model_id
        if model_provider:
            session.model_provider = model_provider

        raw_sections = body.get("sections") or []
        sections: List[Dict[str, Any]] = []
        if isinstance(raw_sections, list):
            for item in raw_sections:
                if not isinstance(item, dict):
                    continue
                name = item.get("name")
                bytes_value = item.get("bytes")
                if not isinstance(name, str) or not isinstance(bytes_value, int):
                    continue
                if bytes_value <= 0:
                    continue
                sections.append({"name": name, "bytes": bytes_value})

        estimated_input_tokens = body.get("estimated_input_tokens")
        if not isinstance(estimated_input_tokens, int):
            estimated_input_tokens = None

        context_window_size = body.get("context_window_size")
        if not isinstance(context_window_size, int):
            context_window_size = 0

        self._pending_context[session_id] = PendingContextBreakdown(
            model_id=model_id,
            model_provider=model_provider,
            context_window_size=context_window_size,
            estimated_input_tokens=estimated_input_tokens,
            sections=sections,
        )

    def _handle_message_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Begin tracking an LLM call."""
        session = self._get_or_create_session(session_id)
        span_id = _format_span_id()
        parent_id = self._current_parent_id(session)
        now_ns = int(time.time() * 1_000_000_000)
        self._pending_llm[session_id] = PendingLLMSpan(
            span_id=span_id,
            parent_id=parent_id,
            start_ns=now_ns,
        )

    def _handle_message_end(self, session_id: str, body: Dict[str, Any]) -> None:
        """Emit an LLM span with token usage and tool calls."""
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return

        now_ns = int(time.time() * 1_000_000_000)
        pending = self._pending_llm.pop(session_id, None)

        if pending:
            span_id = pending.span_id
            parent_id = pending.parent_id
            start_ns = pending.start_ns
        else:
            span_id = _format_span_id()
            parent_id = self._current_parent_id(session)
            start_ns = now_ns

        duration = now_ns - start_ns

        model_id = body.get("model_id", session.model)
        model_provider = body.get("model_provider", session.model_provider)
        usage = body.get("usage") or {}
        output_text = body.get("output_text", "")
        tool_calls = body.get("tool_calls", [])
        stop_reason = body.get("stop_reason", "")
        pending_context = self._pending_context.pop(session_id, None)

        if model_id:
            session.model = model_id
        if model_provider:
            session.model_provider = model_provider

        # Build input/output messages in LLMObs format
        output_messages = []
        if output_text:
            output_messages.append({"content": output_text, "role": "assistant"})
        if tool_calls:
            for tc in tool_calls:
                output_messages.append({
                    "content": json.dumps(tc.get("arguments", {})),
                    "role": "assistant",
                    "tool_calls": [{"name": tc.get("name", ""), "arguments": tc.get("arguments", {})}],
                })

        # Token metrics
        input_tokens = usage.get("input", 0)
        output_tokens = usage.get("output", 0)
        cache_read = usage.get("cacheRead", 0)
        cache_write = usage.get("cacheWrite", 0)
        total_input_tokens = input_tokens + cache_read + cache_write
        total_tokens = usage.get("totalTokens", 0) or (total_input_tokens + output_tokens)

        # Cost: prefer provider-reported cost, fall back to model-based estimate
        provider_cost = usage.get("cost")
        cost_metrics: Dict[str, int] = {}
        if isinstance(provider_cost, dict) and provider_cost.get("total", 0) > 0:
            cost_metrics = cost_from_provider_usage(provider_cost)
        else:
            cost_metrics = compute_cost_metrics(
                model_id=model_id or "",
                non_cached_input_tokens=input_tokens,
                cache_write_tokens=cache_write,
                cache_read_tokens=cache_read,
                output_tokens=output_tokens,
            ) or {}

        context_breakdown = self._compute_context_breakdown(
            pending_context,
            total_input_tokens if total_input_tokens > 0 else (pending_context.estimated_input_tokens if pending_context else 0),
            model_id or session.model,
        )

        span: Dict[str, Any] = {
            "span_id": span_id,
            "trace_id": session.trace_id,
            "parent_id": parent_id,
            "name": model_id or "unknown",
            "status": "ok",
            "start_ns": start_ns,
            "duration": duration,
            "ml_app": _ML_APP,
            "service": _ML_APP,
            "env": "local",
            "session_id": session.session_id,
            "tags": [
                f"ml_app:{_ML_APP}",
                f"session_id:{session.session_id}",
                f"service:{_ML_APP}",
                "env:local",
                "source:pi-hooks",
                "language:python",
                f"hostname:{_HOSTNAME}",
            ],
            "meta": {
                "span": {"kind": "llm"},
                "model_name": model_id,
                "model_provider": model_provider,
                "input": {"messages": []},
                "output": {"messages": output_messages},
                "metadata": {
                    "stop_reason": stop_reason,
                },
            },
            "metrics": {
                "input_tokens": total_input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
                "cache_read_input_tokens": cache_read,
                "cache_write_input_tokens": cache_write,
                "non_cached_input_tokens": input_tokens,
                **cost_metrics,
            },
        }
        if context_breakdown:
            self._hooks_api._set_hidden_metadata(span, context_breakdown=context_breakdown)
        self._append_span(span)

    def _handle_tool_execution_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Create a pending tool span (equivalent to PreToolUse)."""
        session = self._get_or_create_session(session_id)
        tool_name = body.get("tool_name", "unknown_tool")
        tool_call_id = body.get("tool_call_id", tool_name)
        args = body.get("args", "")
        session.tools_used.add(tool_name)

        span_id = _format_span_id()
        parent_id = self._current_parent_id(session)
        now_ns = int(time.time() * 1_000_000_000)

        # Parse args string back to dict for tool_input if possible
        tool_input: Any = args
        if isinstance(args, str):
            try:
                tool_input = json.loads(args)
            except (json.JSONDecodeError, ValueError):
                tool_input = args

        session.pending_tools[tool_call_id] = PendingToolSpan(
            span_id=span_id,
            tool_name=tool_name,
            tool_input=tool_input,
            parent_id=parent_id,
            start_ns=now_ns,
        )

    def _handle_tool_execution_end(self, session_id: str, body: Dict[str, Any]) -> None:
        """Emit a tool span (equivalent to PostToolUse/PostToolUseFailure)."""
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return

        tool_name = body.get("tool_name", "unknown_tool")
        tool_call_id = body.get("tool_call_id", tool_name)
        result = body.get("result", "")
        is_error = body.get("is_error", False)

        now_ns = int(time.time() * 1_000_000_000)
        pending = session.pending_tools.pop(tool_call_id, None)

        if pending:
            span_id = pending.span_id
            parent_id = pending.parent_id
            start_ns = pending.start_ns
            input_value = _to_json_str(pending.tool_input) if pending.tool_input else ""
            actual_tool_name = pending.tool_name
        else:
            span_id = _format_span_id()
            parent_id = self._current_parent_id(session)
            start_ns = now_ns
            input_value = ""
            actual_tool_name = tool_name

        duration = now_ns - start_ns
        output_str = _to_json_str(result) if result else ""

        span: Dict[str, Any] = {
            "span_id": span_id,
            "trace_id": session.trace_id,
            "parent_id": parent_id,
            "name": actual_tool_name,
            "status": "error" if is_error else "ok",
            "start_ns": start_ns,
            "duration": duration,
            "ml_app": _ML_APP,
            "service": _ML_APP,
            "env": "local",
            "session_id": session.session_id,
            "tags": [
                f"ml_app:{_ML_APP}",
                f"session_id:{session.session_id}",
                f"service:{_ML_APP}",
                "env:local",
                "source:pi-hooks",
                "language:python",
                f"hostname:{_HOSTNAME}",
                f"tool_name:{actual_tool_name}",
            ],
            "meta": {
                "span": {"kind": "tool"},
                "input": {"value": input_value},
                "output": {"value": output_str},
                "metadata": {"tool_id": tool_call_id},
            },
            "metrics": {},
        }
        if is_error:
            span["meta"]["error"] = {"message": output_str}
        self._append_span(span)

    def _handle_session_compact(self, session_id: str, body: Dict[str, Any]) -> None:
        """Mark compaction event on the current active span."""
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        span_ref = self._hooks_api._current_span_ref(session)
        if span_ref is None:
            return
        dd = span_ref.setdefault("meta", {}).setdefault("metadata", {}).setdefault("_dd", {})
        dd.setdefault("compactions", []).append({
            "trigger": "auto" if body.get("from_extension") else "manual",
        })

    def _handle_turn_start(self, session_id: str, body: Dict[str, Any]) -> None:
        log.debug("Pi turn_start for session %s: turn_index=%s", session_id, body.get("turn_index"))

    def _handle_turn_end(self, session_id: str, body: Dict[str, Any]) -> None:
        log.debug("Pi turn_end for session %s: turn_index=%s", session_id, body.get("turn_index"))

    def _handle_session_shutdown(self, session_id: str, body: Dict[str, Any]) -> None:
        """Finalize session (equivalent to SessionEnd)."""
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        self._pending_context.pop(session_id, None)
        if not session.root_span_emitted:
            self._hooks_api._finalize_interrupted_turn(session)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    _HANDLERS: Dict[str, str] = {
        "session_start": "_handle_session_start",
        "session_shutdown": "_handle_session_shutdown",
        "model_select": "_handle_model_select",
        "agent_start": "_handle_agent_start",
        "agent_end": "_handle_agent_end",
        "turn_start": "_handle_turn_start",
        "turn_end": "_handle_turn_end",
        "provider_request_context": "_handle_provider_request_context",
        "message_start": "_handle_message_start",
        "message_end": "_handle_message_end",
        "tool_execution_start": "_handle_tool_execution_start",
        "tool_execution_end": "_handle_tool_execution_end",
        "session_compact": "_handle_session_compact",
    }

    def _dispatch(self, body: Dict[str, Any]) -> None:
        session_id = body.get("session_id", "")
        event_name = body.get("hook_event_name", "")
        handler_name = self._HANDLERS.get(event_name)
        if handler_name:
            handler = getattr(self, handler_name)
            handler(session_id, body)
        else:
            log.debug("Unhandled pi hook event: %s", event_name)

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

    async def handle_hook(self, request: Request) -> web.Response:
        """Handle POST /pi/hooks — receives pi extension JSON and dispatches by event name."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)

        session_id = body.get("session_id", "")
        if not session_id:
            return web.json_response({"error": "missing session_id"}, status=400)

        self._raw_events.append(body)
        self._dispatch(body)

        hook_event_name = body.get("hook_event_name", "")

        # Forward completed traces to backend on agent_end or session_shutdown
        if hook_event_name in ("agent_end", "session_shutdown"):
            await self._hooks_api._forward_trace_to_backend(session_id)
            await self._hooks_api._forward_eval_metrics_to_backend(session_id)

        return web.json_response({"status": "ok"})

    async def handle_raw_events(self, request: Request) -> web.Response:
        """Handle GET /pi/hooks/raw — return all raw received events for debugging."""
        return web.json_response({"events": self._raw_events})

    def get_routes(self) -> List[web.RouteDef]:
        """Return the routes for this API."""
        return [
            web.post("/pi/hooks", with_cors(self.handle_hook)),
            web.route("*", "/pi/hooks/raw", with_cors(self.handle_raw_events)),
        ]
