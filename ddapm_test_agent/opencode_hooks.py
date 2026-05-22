"""OpenCode Coding Agent Hooks → LLM Observability Spans.

Receives lifecycle events from the opencode lapdog plugin via HTTP and
assembles them into LLMObs-format spans.  Reuses the ClaudeHooksAPI's session
state and span storage so opencode traces appear alongside Claude Code, Codex,
and Pi traces in the UI.

OpenCode plugin events and their mapping (event name on the wire → effect)::

    session_start          → create session, set initial model (if known)
    model_select           → update session model
    user_message           → start a new turn (root agent span)
    assistant_message      → emit one LLM span (start ns / end ns from the
                             message's time.created / time.completed, usage →
                             tokens + cost). Also opens/closes a step span if
                             one is not already open for this turn.
    tool_execute_before    → create pending tool span (child of step)
    tool_execute_after     → emit tool span
    session_compact        → mark compaction on the current span
    session_idle           → finalize root span (turn done)
    session_end            → finalize interrupted turn + close session

The opencode plugin uses ``message.updated`` events for both user and
assistant messages.  The plugin debounces and only forwards an
``assistant_message`` once ``time.completed`` is set, so each event carries a
complete LLM call with token usage.
"""

import json
import logging
import os
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from aiohttp import web
from aiohttp.web import Request

from ._clock import monotonic_wall_ns
from .claude_cost_tracker import compute_cost_metrics
from .claude_cost_tracker import cost_from_provider_usage
from .claude_hooks import ClaudeHooksAPI
from .claude_hooks import PendingToolSpan
from .claude_hooks import SessionState
from .claude_hooks import _HOSTNAME
from .claude_hooks import _USER_HANDLE
from .claude_hooks import _format_span_id
from .claude_hooks import _format_trace_id
from .claude_hooks import _to_json_str
from .llmobs_event_platform import with_cors


log = logging.getLogger(__name__)

_ML_APP = os.environ.get("DD_OPENCODE_ML_APP", "opencode")
_SOURCE_TAG = "source:opencode-hooks"


def _opencode_part_text(part: Dict[str, Any]) -> str:
    """Extract plain text from a single opencode message part."""
    ptype = part.get("type", "")
    if ptype == "text":
        return str(part.get("text", ""))
    if ptype == "reasoning":
        return ""
    return ""


def _opencode_message_text(content: Any) -> str:
    """Flatten an opencode user / assistant message body to plain text.

    ``content`` may be a bare string, a single dict, or a list of part dicts.
    Tool-use parts and reasoning blocks are ignored — callers that need them
    pull them off the raw ``parts`` array instead.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        return _opencode_part_text(content)
    if not isinstance(content, list):
        return ""
    parts: List[str] = []
    for part in content:
        if isinstance(part, dict):
            text = _opencode_part_text(part)
            if text:
                parts.append(text)
    return "\n".join(parts)


def _extract_assistant_output(parts: Any) -> Tuple[str, List[Dict[str, Any]]]:
    """Parse an assistant message's ``parts`` into (output_text, tool_calls).

    opencode assistant messages emit a list of typed parts.  We care about
    ``text`` (collapsed into output_text) and ``tool`` (forwarded as tool
    calls in LLMObs format).
    """
    text_parts: List[str] = []
    tool_calls: List[Dict[str, Any]] = []
    if not isinstance(parts, list):
        return "", []
    for part in parts:
        if not isinstance(part, dict):
            continue
        ptype = part.get("type", "")
        if ptype == "text":
            text = part.get("text", "")
            if text:
                text_parts.append(str(text))
        elif ptype == "tool":
            # opencode tool parts look like {type: tool, tool: <name>, callID,
            # state: {input, output, ...}}.  We surface the name + input
            # arguments so the LLM span shows what the model decided to call.
            state = part.get("state") or {}
            args = state.get("input") if isinstance(state, dict) else {}
            tool_calls.append(
                {
                    "id": part.get("callID", ""),
                    "name": part.get("tool", ""),
                    "arguments": args if args is not None else {},
                }
            )
    return "\n".join(text_parts), tool_calls


class PendingLLMSpan:
    """Tracks an LLM call between user_message and assistant_message."""

    def __init__(
        self,
        span_id: str,
        parent_id: str,
        start_ns: int,
        input_messages: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        self.span_id = span_id
        self.parent_id = parent_id
        self.start_ns = start_ns
        self.input_messages: List[Dict[str, Any]] = input_messages or []


class ActiveStepSpan:
    """Tracks the active step (one inference cycle) for a session."""

    def __init__(
        self,
        span_id: str,
        parent_id: str,
        start_ns: int,
        message_index: int,
    ) -> None:
        self.span_id = span_id
        self.parent_id = parent_id
        self.start_ns = start_ns
        self.message_index = message_index
        self.output_text = ""
        self.tool_use_ids: List[str] = []
        self.stop_reason = ""
        self.span_ref: Optional[Dict[str, Any]] = None


class OpenCodeHooksAPI:
    """Handler for opencode coding agent hook events.

    Delegates to a shared ClaudeHooksAPI for session/span storage and backend
    forwarding so opencode traces are queryable through the same Event
    Platform APIs as Claude / Codex / Pi sessions.
    """

    def __init__(self, hooks_api: ClaudeHooksAPI) -> None:
        self._hooks_api = hooks_api
        self._raw_events: List[Dict[str, Any]] = []
        # Latest user prompt awaiting attachment to an LLM span's input
        self._pending_user_prompts: Dict[str, str] = {}
        # In-flight LLM span per session
        self._pending_llm: Dict[str, PendingLLMSpan] = {}
        # Active step span per session
        self._active_steps: Dict[str, ActiveStepSpan] = {}
        # Per-session step counter (resets each turn)
        self._step_indexes: Dict[str, int] = {}

    # ------------------------------------------------------------------
    # Helpers — access shared state via hooks_api
    # ------------------------------------------------------------------

    def _get_or_create_session(self, session_id: str) -> SessionState:
        return self._hooks_api._get_or_create_session(session_id)

    def _current_parent_id(self, session: SessionState) -> str:
        return self._hooks_api._current_parent_id(session)

    def _append_span(self, span: Dict[str, Any]) -> None:
        self._hooks_api._assembled_spans.append(span)

    def _active_step_parent_id(self, session: SessionState) -> str:
        active = self._active_steps.get(session.session_id)
        if active:
            return active.span_id
        return self._current_parent_id(session)

    def _base_tags(self, session: SessionState, semantic_type: Optional[str] = None) -> List[str]:
        tags = [
            f"ml_app:{_ML_APP}",
            f"session_id:{session.session_id}",
            f"service:{_ML_APP}",
            "env:local",
            _SOURCE_TAG,
            "language:python",
            f"hostname:{_HOSTNAME}",
        ]
        if semantic_type:
            tags.append(f"trajectory.semantic_type:{semantic_type}")
        if _USER_HANDLE:
            tags.append(f"user_handle:{_USER_HANDLE}")
        return tags

    # ------------------------------------------------------------------
    # Step lifecycle helpers
    # ------------------------------------------------------------------

    def _start_step(self, session: SessionState, start_ns: Optional[int] = None) -> ActiveStepSpan:
        sid = session.session_id
        self._finalize_active_step(sid, end_ns=start_ns)

        idx = self._step_indexes.get(sid, 0)
        self._step_indexes[sid] = idx + 1

        now_ns = start_ns if start_ns is not None else monotonic_wall_ns()
        span_id = _format_span_id()
        parent_id = self._current_parent_id(session)

        step_span: Dict[str, Any] = {
            "span_id": span_id,
            "trace_id": session.trace_id,
            "parent_id": parent_id,
            "name": f"inference-{idx}",
            "status": "ok",
            "start_ns": now_ns,
            "duration": 0,
            "ml_app": _ML_APP,
            "service": _ML_APP,
            "env": "local",
            "session_id": session.session_id,
            "tags": self._base_tags(session, semantic_type="agent_message"),
            "meta": {
                "span": {"kind": "step"},
                "input": {},
                "output": {"value": ""},
                "metadata": {},
            },
            "metrics": {},
        }
        self._append_span(step_span)

        active = ActiveStepSpan(
            span_id=span_id,
            parent_id=parent_id,
            start_ns=now_ns,
            message_index=idx,
        )
        active.span_ref = step_span
        self._active_steps[sid] = active
        return active

    def _finalize_active_step(self, session_id: str, end_ns: Optional[int] = None) -> None:
        active = self._active_steps.pop(session_id, None)
        if not active:
            return
        if end_ns is None:
            end_ns = monotonic_wall_ns()
        ref = active.span_ref
        if ref is None:
            return
        if end_ns < active.start_ns:
            end_ns = active.start_ns + 1
        ref["duration"] = end_ns - active.start_ns
        ref["meta"]["output"]["value"] = active.output_text
        metadata = ref["meta"].setdefault("metadata", {})
        metadata["message_index"] = active.message_index
        if active.tool_use_ids:
            metadata["tool_use_ids"] = active.tool_use_ids
        if active.stop_reason:
            metadata["stop_reason"] = active.stop_reason

    def _clear_opencode_state(self, session_id: str) -> None:
        self._active_steps.pop(session_id, None)
        self._step_indexes[session_id] = 0
        self._pending_llm.pop(session_id, None)
        self._pending_user_prompts.pop(session_id, None)

    def _ensure_root_span(self, session: SessionState, prompt: str = "") -> None:
        """Create the root agent span for a turn if one is not already open.

        opencode does not have an explicit ``agent_start`` event.  The first
        ``user_message`` after a fresh session (or after a previous turn
        finalized) opens the turn; subsequent ``user_message``s within the
        same idle cycle just append to ``session.user_prompts``.
        """
        if getattr(session, "_root_span_ref", None) is not None and not session.root_span_emitted:
            return

        # Fresh trace for the new turn (either first-ever or after the prior
        # turn finalized via session_idle).
        if session.root_span_emitted:
            now_ns = monotonic_wall_ns()
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
            session.models = [session.model] if session.model else []

        self._clear_opencode_state(session.session_id)

        if prompt:
            session.user_prompts.append(prompt)

        root_span: Dict[str, Any] = {
            "span_id": session.root_span_id,
            "trace_id": session.trace_id,
            "parent_id": "undefined",
            "name": "opencode-request",
            "status": "ok",
            "start_ns": session.start_ns,
            "duration": 0,
            "ml_app": _ML_APP,
            "service": _ML_APP,
            "env": "local",
            "session_id": session.session_id,
            "tags": self._base_tags(session, semantic_type="turn"),
            "meta": {
                "span": {"kind": "agent"},
                "input": {"value": prompt},
                "output": {"value": ""},
                "model_name": session.model,
                "model_provider": session.model_provider,
                "metadata": {"models_used": session.models[:]},
            },
            "metrics": {},
        }
        self._append_span(root_span)
        session._root_span_ref = root_span  # type: ignore[attr-defined]

    def _finalize_root_span(self, session: SessionState, end_ns: Optional[int] = None) -> None:
        if session.root_span_emitted:
            return

        self._finalize_active_step(session.session_id, end_ns=end_ns)

        if end_ns is None:
            end_ns = monotonic_wall_ns()
        duration = end_ns - session.start_ns
        if duration < 0:
            duration = 0
        input_value = "\n\n".join(session.user_prompts) if session.user_prompts else ""

        # Use the last assistant output_text we recorded as the turn output.
        # We stash it on the session via a private attribute set in
        # _handle_assistant_message; fall back to empty.
        output_value = getattr(session, "_opencode_last_assistant_text", "")

        tool_usage = self._hooks_api._aggregate_tool_usage(session.trace_id)

        root_span = getattr(session, "_root_span_ref", None)
        if root_span is None:
            root_span = next(
                (s for s in self._hooks_api._assembled_spans if s.get("span_id") == session.root_span_id),
                None,
            )

        if root_span is None:
            return

        root_span["duration"] = duration
        root_span["meta"]["input"]["value"] = input_value
        root_span["meta"]["output"]["value"] = output_value
        root_span["meta"]["model_name"] = session.model
        root_span["meta"]["model_provider"] = session.model_provider
        root_span["meta"].setdefault("metadata", {})["models_used"] = session.models[:]
        dd_fields: Dict[str, Any] = {}
        if tool_usage:
            dd_fields["tool_usage"] = tool_usage
        dd_fields["agent_manifest"] = {
            "name": _ML_APP,
            "model": session.model,
            "model_provider": session.model_provider,
            "models": session.models[:],
            "tools": [{"name": name} for name in sorted(session.tools_used)],
        }
        if dd_fields:
            self._hooks_api._set_hidden_metadata(root_span, **dd_fields)

        session.root_span_emitted = True

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _handle_session_start(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        model_id = body.get("model_id", "") or ""
        model_provider = body.get("model_provider", "") or ""
        if model_id:
            session.model = model_id
            if not session.models or session.models[-1] != model_id:
                session.models.append(model_id)
        if model_provider:
            session.model_provider = model_provider
        log.info("opencode session started: %s (model=%s/%s)", session_id, model_provider, model_id)

    def _handle_model_select(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        model_id = body.get("model_id", "") or ""
        model_provider = body.get("model_provider", "") or ""
        if model_id:
            session.model = model_id
            if not session.models or session.models[-1] != model_id:
                session.models.append(model_id)
        if model_provider:
            session.model_provider = model_provider

    def _handle_user_message(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        content = body.get("content", "")
        prompt = content if isinstance(content, str) else _opencode_message_text(content)
        self._ensure_root_span(session, prompt=prompt)
        # If the root span was already open for this turn, _ensure_root_span
        # skips the append; append the prompt manually so multi-turn
        # follow-ups inside one "turn" are still recorded.
        if prompt and (not session.user_prompts or session.user_prompts[-1] != prompt):
            session.user_prompts.append(prompt)
        self._pending_user_prompts[session_id] = prompt

    def _handle_assistant_message(self, session_id: str, body: Dict[str, Any]) -> None:
        """Emit a single LLM span for a completed assistant message."""
        session = self._get_or_create_session(session_id)

        # If somehow we got an assistant_message before any user_message, open
        # a synthetic turn so the LLM has somewhere to live.
        self._ensure_root_span(session, prompt=self._pending_user_prompts.get(session_id, ""))

        model_id = body.get("model_id", "") or ""
        model_provider = body.get("model_provider", "") or ""
        if model_id:
            session.model = model_id
            if not session.models or session.models[-1] != model_id:
                session.models.append(model_id)
        if model_provider:
            session.model_provider = model_provider

        start_ns = body.get("start_ns") or 0
        end_ns = body.get("end_ns") or 0
        if not isinstance(start_ns, int):
            try:
                start_ns = int(start_ns)
            except (TypeError, ValueError):
                start_ns = 0
        if not isinstance(end_ns, int):
            try:
                end_ns = int(end_ns)
            except (TypeError, ValueError):
                end_ns = 0
        now_ns = monotonic_wall_ns()
        if start_ns <= 0:
            start_ns = now_ns
        if end_ns <= 0 or end_ns < start_ns:
            end_ns = max(now_ns, start_ns + 1)

        # Open a step span for this inference if one isn't open yet (e.g. the
        # very first assistant message of a turn).  The step starts at the
        # LLM start so its duration covers the inference + any downstream
        # tools.
        if session_id not in self._active_steps:
            self._start_step(session, start_ns=start_ns)

        parent_id = self._active_step_parent_id(session)

        # Build LLM input.messages: a synthetic system isn't available here,
        # but the latest user prompt is.
        prompt = self._pending_user_prompts.get(session_id, "")
        input_messages: List[Dict[str, Any]] = []
        if prompt:
            input_messages.append({"role": "user", "content": prompt})

        # Parse assistant parts → output_text + tool_calls
        parts = body.get("parts") or []
        output_text, tool_calls = _extract_assistant_output(parts)

        # Update active step metadata
        active = self._active_steps.get(session_id)
        if active:
            if output_text:
                active.output_text = output_text
            for tc in tool_calls:
                tid = tc.get("id", "")
                if tid and tid not in active.tool_use_ids:
                    active.tool_use_ids.append(tid)

        # Stash for the root span's output.value on session_idle.
        if output_text:
            session._opencode_last_assistant_text = output_text  # type: ignore[attr-defined]

        # Build output messages
        output_messages: List[Dict[str, Any]] = []
        if output_text:
            output_messages.append({"content": output_text, "role": "assistant"})
        for tc in tool_calls:
            output_messages.append(
                {
                    "content": json.dumps(tc.get("arguments", {})),
                    "role": "assistant",
                    "tool_calls": [{"name": tc.get("name", ""), "arguments": tc.get("arguments", {})}],
                }
            )

        # Tokens — opencode exposes either:
        #   { input, output, reasoning, cache: { read, write } }
        # or a flat dict.  Be defensive.
        tokens = body.get("tokens") or {}
        input_tokens = int(tokens.get("input", 0) or 0)
        output_tokens = int(tokens.get("output", 0) or 0)
        reasoning_tokens = int(tokens.get("reasoning", 0) or 0)
        cache = tokens.get("cache") or {}
        if not isinstance(cache, dict):
            cache = {}
        cache_read = int(cache.get("read", 0) or 0)
        cache_write = int(cache.get("write", 0) or 0)
        total_tokens = int(tokens.get("total", 0) or 0) or (
            input_tokens + output_tokens + reasoning_tokens + cache_read + cache_write
        )

        # Cost: prefer provider-reported total, fall back to estimated.
        provider_cost = body.get("cost")
        cost_metrics: Dict[str, int] = {}
        if isinstance(provider_cost, dict) and (provider_cost.get("total") or 0) > 0:
            cost_metrics = cost_from_provider_usage(provider_cost)
        elif isinstance(provider_cost, (int, float)) and float(provider_cost) > 0:
            # Sometimes opencode reports a single number — treat as total.
            cost_metrics = cost_from_provider_usage({"total": float(provider_cost)})
        else:
            estimated = compute_cost_metrics(
                model_id=model_id or "",
                non_cached_input_tokens=input_tokens,
                cache_write_tokens=cache_write,
                cache_read_tokens=cache_read,
                output_tokens=output_tokens,
            )
            cost_metrics = estimated or {}

        stop_reason = body.get("stop_reason", "") or ""
        if active and stop_reason:
            active.stop_reason = stop_reason

        span_id = _format_span_id()
        duration = end_ns - start_ns
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
            "tags": self._base_tags(session),
            "meta": {
                "span": {"kind": "llm"},
                "model_name": model_id,
                "model_provider": model_provider,
                "input": {"messages": input_messages},
                "output": {"messages": output_messages},
                "metadata": {
                    "stop_reason": stop_reason,
                },
            },
            "metrics": {
                "input_tokens": input_tokens + cache_read + cache_write,
                "output_tokens": output_tokens + reasoning_tokens,
                "total_tokens": total_tokens,
                "cache_read_input_tokens": cache_read,
                "cache_write_input_tokens": cache_write,
                "non_cached_input_tokens": input_tokens,
                **cost_metrics,
            },
        }
        if reasoning_tokens:
            span["metrics"]["reasoning_tokens"] = reasoning_tokens
        self._append_span(span)

    def _handle_tool_execute_before(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        tool_name = body.get("tool_name", "unknown_tool") or "unknown_tool"
        tool_call_id = body.get("tool_call_id", "") or tool_name
        args = body.get("args", {})
        session.tools_used.add(tool_name)

        span_id = _format_span_id()
        parent_id = self._active_step_parent_id(session)
        now_ns = monotonic_wall_ns()

        session.pending_tools[tool_call_id] = PendingToolSpan(
            span_id=span_id,
            tool_name=tool_name,
            tool_input=args,
            parent_id=parent_id,
            start_ns=now_ns,
        )

    def _handle_tool_execute_after(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if session is None:
            session = self._get_or_create_session(session_id)
            self._ensure_root_span(session)

        tool_name = body.get("tool_name", "unknown_tool") or "unknown_tool"
        tool_call_id = body.get("tool_call_id", "") or tool_name
        result = body.get("result", "")
        is_error = bool(body.get("is_error", False))
        error = body.get("error")

        now_ns = monotonic_wall_ns()
        pending = session.pending_tools.pop(tool_call_id, None)

        if pending is not None:
            span_id = pending.span_id
            parent_id = pending.parent_id
            start_ns = pending.start_ns
            input_value = _to_json_str(pending.tool_input) if pending.tool_input else ""
            actual_tool_name = pending.tool_name
        else:
            span_id = _format_span_id()
            parent_id = self._active_step_parent_id(session)
            start_ns = now_ns
            input_value = _to_json_str(body.get("args")) if body.get("args") else ""
            actual_tool_name = tool_name
            # Record for the tool_usage rollup even on fallback path.
            session.tools_used.add(actual_tool_name)

        duration = now_ns - start_ns
        if duration < 0:
            duration = 0

        output_str = _to_json_str(result) if result not in ("", None) else ""

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
            "tags": self._base_tags(session) + [f"tool_name:{actual_tool_name}"],
            "meta": {
                "span": {"kind": "tool"},
                "input": {"value": input_value},
                "output": {"value": output_str},
                "model_name": session.model,
                "model_provider": session.model_provider,
                "metadata": {"tool_id": tool_call_id},
            },
            "metrics": {},
        }
        if is_error:
            err_msg = ""
            if isinstance(error, str):
                err_msg = error
            elif isinstance(error, dict):
                err_msg = str(error.get("message") or _to_json_str(error))
            else:
                err_msg = output_str
            span["meta"]["error"] = {"message": err_msg}
        self._append_span(span)

    def _handle_session_compact(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        span_ref = self._hooks_api._current_span_ref(session)
        if span_ref is None:
            return
        dd = span_ref.setdefault("meta", {}).setdefault("metadata", {}).setdefault("_dd", {})
        dd.setdefault("compactions", []).append(
            {"trigger": body.get("trigger") or "auto"},
        )

    def _handle_session_idle(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        self._finalize_root_span(session)

    def _handle_session_end(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        self._finalize_active_step(session_id)
        if not session.root_span_emitted:
            self._hooks_api._finalize_interrupted_turn(session)

    # ------------------------------------------------------------------
    # Dispatch
    # ------------------------------------------------------------------

    _HANDLERS: Dict[str, str] = {
        "session_start": "_handle_session_start",
        "model_select": "_handle_model_select",
        "user_message": "_handle_user_message",
        "assistant_message": "_handle_assistant_message",
        "tool_execute_before": "_handle_tool_execute_before",
        "tool_execute_after": "_handle_tool_execute_after",
        "session_compact": "_handle_session_compact",
        "session_idle": "_handle_session_idle",
        "session_end": "_handle_session_end",
    }

    def _dispatch(self, body: Dict[str, Any]) -> None:
        session_id = body.get("session_id", "") or ""
        event_name = body.get("hook_event_name", "") or ""
        handler_name = self._HANDLERS.get(event_name)
        if handler_name:
            handler = getattr(self, handler_name)
            handler(session_id, body)
        else:
            log.debug("Unhandled opencode hook event: %s", event_name)

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

    async def handle_hook(self, request: Request) -> web.Response:
        """Handle POST /opencode/hooks."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)

        if not isinstance(body, dict):
            return web.json_response({"error": "expected JSON object"}, status=400)

        session_id = body.get("session_id", "")
        if not session_id:
            return web.json_response({"error": "missing session_id"}, status=400)

        self._raw_events.append(body)
        self._dispatch(body)

        hook_event_name = body.get("hook_event_name", "")
        if hook_event_name in ("session_idle", "session_end"):
            await self._hooks_api._forward_trace_to_backend(session_id)
            await self._hooks_api._forward_eval_metrics_to_backend(session_id)

        return web.json_response({"status": "ok"})

    async def handle_raw_events(self, request: Request) -> web.Response:
        """Handle GET /opencode/hooks/raw — return raw received events for debugging."""
        return web.json_response({"events": self._raw_events})

    def get_routes(self) -> List[web.RouteDef]:
        """Return the routes for this API."""
        return [
            web.post("/opencode/hooks", with_cors(self.handle_hook)),
            web.route("*", "/opencode/hooks/raw", with_cors(self.handle_raw_events)),
        ]
