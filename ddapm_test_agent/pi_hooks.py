"""Pi Coding Agent Hooks → LLM Observability Spans.

Receives lifecycle events from the pi lapdog extension via HTTP and assembles
them into LLMObs-format spans.  Reuses the ClaudeHooksAPI's session state and
span storage so that pi traces appear alongside Claude Code traces in the UI.

Pi extension events and their mapping:

    session_start     → create session, set model
    agent_start       → start new trace / root agent span (proposal "turn")
    agent_end         → finalize root span
    turn_start        → open a step span (proposal "step" = one inference cycle)
    turn_end          → finalize step span
    message_start     → begin tracking an LLM span (child of step)
    message_end       → emit LLM span with token usage
    tool_execution_start → create pending tool span (child of step)
    tool_execution_end   → emit tool span
    model_select      → update session model
    session_compact   → mark compaction on current span
    session_shutdown  → finalize session (like SessionEnd)

Terminology mapping (pi → trajectory-dev proposal):
    pi agent_start/agent_end  →  proposal "turn" (full response to one user input)
    pi turn_start/turn_end    →  proposal "step" (one inference cycle + its tools)
    pi message_start/end      →  proposal LLM call within a step
"""

import json
import logging
import os
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import cast

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
from .codex_cost_tracker import compute_openai_cost_metrics
from .coding_agent_metadata import apply_project_metadata_to_span
from .coding_agent_metadata import project_metadata_tags
from .llmobs_event_platform import with_cors

log = logging.getLogger(__name__)

_ML_APP = os.environ.get("DD_PI_CODING_AGENT_ML_APP", "pi-coding-agent")
_AI_GATEWAY_COST_PROVIDERS = frozenset({"anthropic", "openai"})


def _split_ai_gateway_model_id(model_id: str) -> Tuple[Optional[str], str]:
    """Return (provider, model) for AI Gateway-style IDs like ``openai/gpt-5.5``."""
    provider, _, model = model_id.partition("/")
    normalized_provider = provider.lower()
    if model and normalized_provider in _AI_GATEWAY_COST_PROVIDERS:
        return normalized_provider, model
    return None, model_id


def _looks_like_openai_model(model_id: str) -> bool:
    return model_id.lower().startswith("gpt-")


def _has_provider_cost(provider_cost: Any) -> bool:
    if not isinstance(provider_cost, dict):
        return False
    for key in ("input", "output", "cacheRead", "cacheWrite", "total"):
        value = provider_cost.get(key, 0)
        if isinstance(value, bool):
            continue
        if isinstance(value, (int, float)) and value > 0:
            return True
    return False


def _compute_pi_cost_metrics(
    model_id: str,
    model_provider: str,
    non_cached_input_tokens: int,
    cache_write_tokens: int,
    cache_read_tokens: int,
    output_tokens: int,
) -> Dict[str, int]:
    cost_provider, pricing_model_id = _split_ai_gateway_model_id(model_id)
    provider = cost_provider or model_provider.lower()

    if provider == "openai" or _looks_like_openai_model(pricing_model_id):
        return compute_openai_cost_metrics(
            model_id=pricing_model_id,
            non_cached_input_tokens=non_cached_input_tokens + cache_write_tokens,
            cached_input_tokens=cache_read_tokens,
            output_tokens=output_tokens,
        )

    anthropic_cost = compute_cost_metrics(
        model_id=pricing_model_id,
        non_cached_input_tokens=non_cached_input_tokens,
        cache_write_tokens=cache_write_tokens,
        cache_read_tokens=cache_read_tokens,
        output_tokens=output_tokens,
    )
    if anthropic_cost is not None:
        return anthropic_cost

    return {}


class PendingLLMSpan:
    """Tracks an LLM call between message_start and message_end."""

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
    """Tracks the active step (inference cycle) for a session.

    A step groups one LLM call and its downstream tool executions.
    It maps to a ``turn_start`` / ``turn_end`` pair in pi's event model and
    to the ``step`` span kind in the trajectory-dev proposal.
    """

    def __init__(
        self,
        span_id: str,
        parent_id: str,
        start_ns: int,
        message_index: int,
        turn_index: Optional[int] = None,
    ) -> None:
        self.span_id = span_id
        self.parent_id = parent_id
        self.start_ns = start_ns
        self.message_index = message_index
        self.turn_index = turn_index
        self.output_text = ""
        self.tool_use_ids: List[str] = []
        self.has_thinking = False
        self.stop_reason = ""
        self.span_ref: Optional[Dict[str, Any]] = None


def _pi_content_to_text(content: Any) -> str:
    """Flatten a pi message ``content`` field to plain text.

    pi messages use either a string or a list of typed content blocks
    (``text``, ``image``, ``thinking``, ``toolCall``).  For the LLMObs span
    input we want a single string — image and thinking blocks are summarized
    as ``[image]`` / ``[thinking]`` placeholders so they don't get dropped
    silently.
    """
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: List[str] = []
    for block in content:
        if not isinstance(block, dict):
            continue
        btype = block.get("type", "")
        if btype == "text":
            text = block.get("text", "")
            if text:
                parts.append(text)
        elif btype == "image":
            parts.append("[image]")
        elif btype in ("thinking", "reasoning"):
            parts.append("[thinking]")
    return "\n".join(parts)


def _pi_messages_to_llmobs_input(
    system_prompt: str,
    messages: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Convert pi's LLM-shaped messages into LLMObs ``input.messages`` format.

    The extension runs pi's own ``convertToLlm()`` on the ``context`` event
    payload before sending, so by the time messages reach this function they
    are already reduced to plain ``user`` / ``assistant`` / ``toolResult``
    entries — i.e. exactly what the provider receives. Extended types
    (``bashExecution``, ``custom``, ``branchSummary``, ``compactionSummary``)
    have been inlined as user text upstream.

    Mapping:
        * Prepend ``{role: "system"}`` when ``system_prompt`` is non-empty.
        * pi ``user`` → ``{role: "user", content: <text>}``.
        * pi ``assistant`` → ``{role: "assistant", content, tool_calls}``,
          tool_calls shaped like ``claude_proxy.py``'s output.
        * pi ``toolResult`` → ``{role: "tool", content, tool_id}``.
    """
    out: List[Dict[str, Any]] = []
    if system_prompt:
        out.append({"role": "system", "content": system_prompt})

    for msg in messages or []:
        if not isinstance(msg, dict):
            continue
        role = msg.get("role", "")

        if role == "user":
            out.append({"role": "user", "content": _pi_content_to_text(msg.get("content"))})

        elif role == "assistant":
            content = msg.get("content", [])
            text, tool_calls, _tool_use_ids, _has_thinking = _extract_output_text_and_tool_calls(
                content if isinstance(content, list) else []
            )
            entry: Dict[str, Any] = {"role": "assistant", "content": text}
            if tool_calls:
                entry["tool_calls"] = [
                    {
                        "name": tc.get("name", ""),
                        "arguments": tc.get("arguments", {}),
                        "tool_id": tc.get("id", ""),
                        "type": "tool_use",
                    }
                    for tc in tool_calls
                ]
            out.append(entry)

        elif role == "toolResult":
            out.append(
                {
                    "role": "tool",
                    "content": _pi_content_to_text(msg.get("content")),
                    "tool_id": msg.get("toolCallId", ""),
                }
            )

    return out


def _extract_output_text_and_tool_calls(
    content: List[Dict[str, Any]],
) -> Tuple[str, List[Dict[str, Any]], List[str], bool]:
    """Parse assistant message content blocks.

    Returns ``(output_text, tool_calls, tool_use_ids, has_thinking)``.
    """
    text_parts: List[str] = []
    tool_calls: List[Dict[str, Any]] = []
    tool_use_ids: List[str] = []
    has_thinking = False

    for block in content:
        btype = block.get("type", "")
        if btype == "text" and block.get("text"):
            text_parts.append(block["text"])
        elif btype == "toolCall":
            tid = block.get("id", "")
            tool_calls.append({"id": tid, "name": block.get("name"), "arguments": block.get("arguments")})
            if tid:
                tool_use_ids.append(tid)
        elif btype in ("thinking", "reasoning"):
            has_thinking = True

    return "\n".join(text_parts), tool_calls, tool_use_ids, has_thinking


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
        # Active step span per session (one inference cycle)
        self._active_steps: Dict[str, ActiveStepSpan] = {}
        # Per-session step counter (resets each agent cycle)
        self._step_indexes: Dict[str, int] = {}
        # Per-session turn index from extension events
        self._turn_indexes: Dict[str, Optional[int]] = {}

    # ------------------------------------------------------------------
    # Helpers — access shared state via hooks_api
    # ------------------------------------------------------------------

    def _get_or_create_session(self, session_id: str) -> SessionState:
        return self._hooks_api._get_or_create_session(session_id)

    def _current_parent_id(self, session: SessionState) -> str:
        return self._hooks_api._current_parent_id(session)

    def _append_span(self, span: Dict[str, Any]) -> None:
        self._hooks_api._assembled_spans.append(span)

    def _base_tags(self, session: SessionState, source: str = "pi-hooks") -> List[str]:
        tags = [
            f"ml_app:{_ML_APP}",
            f"session_id:{session.session_id}",
            f"service:{_ML_APP}",
            "env:local",
            f"source:{source}",
            "language:python",
            f"hostname:{_HOSTNAME}",
        ]
        if _USER_HANDLE:
            tags.append(f"user_handle:{_USER_HANDLE}")
        tags.extend(project_metadata_tags(session.project_metadata))
        return tags

    def _apply_project_metadata_to_span(self, session: SessionState, span: Dict[str, Any]) -> None:
        apply_project_metadata_to_span(span, session.project_metadata)

    def _active_step_parent_id(self, session: SessionState) -> str:
        """Return active step span_id if one exists, else fall back to root/agent parent."""
        active = self._active_steps.get(session.session_id)
        if active:
            return active.span_id
        return self._current_parent_id(session)

    # ------------------------------------------------------------------
    # Step lifecycle helpers
    # ------------------------------------------------------------------

    def _start_step(self, session: SessionState, turn_index: Optional[int] = None) -> ActiveStepSpan:
        """Open a new step span.  Finalizes any prior active step first."""
        sid = session.session_id
        # Finalize prior step if still open
        self._finalize_active_step(sid)

        # Use current counter value as 0-based index, then advance.
        # After this, _step_indexes[sid] is always (last emitted index + 1).
        idx = self._step_indexes.get(sid, 0)
        self._step_indexes[sid] = idx + 1

        now_ns = monotonic_wall_ns()
        span_id = _format_span_id()
        parent_id = self._current_parent_id(session)

        tags = self._base_tags(session) + ["trajectory.semantic_type:agent_message"]

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
            "tags": tags,
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
            turn_index=turn_index,
        )
        active.span_ref = step_span
        self._active_steps[sid] = active
        return active

    def _finalize_active_step(self, session_id: str, end_ns: Optional[int] = None) -> None:
        """Close the active step span, updating its metadata in-place."""
        active = self._active_steps.pop(session_id, None)
        if not active:
            return

        if end_ns is None:
            end_ns = monotonic_wall_ns()

        ref = active.span_ref
        if ref is None:
            return

        ref["duration"] = end_ns - active.start_ns
        ref["meta"]["output"]["value"] = active.output_text

        metadata = ref["meta"].setdefault("metadata", {})
        metadata["message_index"] = active.message_index
        if active.turn_index is not None:
            metadata["turn_index"] = active.turn_index
        if active.tool_use_ids:
            metadata["tool_use_ids"] = active.tool_use_ids
        if active.has_thinking:
            metadata["has_thinking"] = True
        if active.stop_reason:
            metadata["stop_reason"] = active.stop_reason

    def _clear_pi_state(self, session_id: str) -> None:
        """Reset all pi-local tracking state for a session.

        Call ``_finalize_active_step`` first if the active step should be
        properly closed; this method drops state without finalizing.
        """
        self._active_steps.pop(session_id, None)
        self._step_indexes[session_id] = 0
        self._turn_indexes.pop(session_id, None)
        self._pending_llm.pop(session_id, None)

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _handle_session_start(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        model_id = body.get("model_id", "") or body.get("model", "")
        model_provider = body.get("model_provider", "")
        if model_id:
            session.model = model_id
            if not session.models or session.models[-1] != model_id:
                session.models.append(model_id)
        if model_provider:
            session.model_provider = model_provider
        log.info("Pi session started: %s (model=%s/%s)", session_id, model_provider, model_id)

    def _handle_model_select(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        model_id = body.get("model_id", "") or body.get("model", "")
        model_provider = body.get("model_provider", "")
        if model_id:
            session.model = model_id
            if not session.models or session.models[-1] != model_id:
                session.models.append(model_id)
        if model_provider:
            session.model_provider = model_provider
        log.info("Pi model changed: %s → %s/%s", session_id, model_provider, model_id)

    def _handle_agent_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Start a new trace for each user turn (equivalent to UserPromptSubmit).

        The root agent span represents the proposal's "turn" — the full agentic
        response to one user input.
        """
        session = self._get_or_create_session(session_id)

        # Finalize previous turn if it wasn't finalized
        if not session.root_span_emitted and getattr(session, "_root_span_ref", None) is not None:
            self._finalize_active_step(session_id)
            self._hooks_api._finalize_interrupted_turn(session)

        # Clear pi-local state for the new agent cycle.
        # _finalize_active_step already ran above (if needed), so this
        # second pop from _active_steps is a harmless no-op.
        self._clear_pi_state(session_id)

        # Start fresh trace
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

        prompt = body.get("user_prompt", "")
        if prompt:
            session.user_prompts.append(prompt)

        model_id = body.get("model_id", "") or body.get("model", "") or session.model
        model_provider = body.get("model_provider", session.model_provider)
        if model_id:
            session.model = model_id
            if not session.models or session.models[-1] != model_id:
                session.models.append(model_id)
        if model_provider:
            session.model_provider = model_provider

        tags = self._base_tags(session) + ["trajectory.semantic_type:turn"]

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
            "tags": tags,
            "meta": {
                "span": {"kind": "agent"},
                "input": {"value": prompt},
                "output": {"value": ""},
                "model_name": model_id,
                "model_provider": model_provider,
                "metadata": {"models_used": session.models[:]},
            },
            "metrics": {},
        }
        self._apply_project_metadata_to_span(session, root_span)
        self._append_span(root_span)
        session._root_span_ref = root_span  # type: ignore[attr-defined]

    def _handle_agent_end(self, session_id: str, body: Dict[str, Any]) -> None:
        """Finalize the root span for the current turn (equivalent to Stop)."""
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            log.warning("agent_end for unknown session %s", session_id)
            return

        # Finalize any open step before closing the turn
        self._finalize_active_step(session_id)

        now_ns = monotonic_wall_ns()
        duration = now_ns - session.start_ns
        input_value = "\n\n".join(session.user_prompts) if session.user_prompts else ""

        # Extract output text from the messages array (processing moved from extension)
        messages = body.get("messages", [])
        output_value = ""
        if messages:
            for msg in reversed(messages):
                if msg.get("role") == "assistant":
                    content = msg.get("content", [])
                    if isinstance(content, list):
                        text_parts = [c.get("text", "") for c in content if c.get("type") == "text" and c.get("text")]
                        output_value = "\n".join(text_parts)
                    elif isinstance(content, str):
                        output_value = content
                    if output_value:
                        break
        else:
            output_value = body.get("output", "")  # fallback for older extension format

        tool_usage = self._hooks_api._aggregate_tool_usage(session.trace_id)

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
            root_span["meta"]["model_provider"] = session.model_provider
            root_span["meta"].setdefault("metadata", {})["models_used"] = session.models[:]
            self._apply_project_metadata_to_span(session, root_span)
            # Do not roll token_usage up onto root_span["metrics"] —
            # production stores trace rollups in a separate `@trace.*`
            # document, not on the root span. Mirroring it here caused
            # `_build_trace_aggregates` to double-count tokens.
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
        else:
            # Fallback: create root span
            tags = self._base_tags(session) + ["trajectory.semantic_type:turn"]
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
                "tags": tags,
                "meta": {
                    "span": {"kind": "agent"},
                    "input": {"value": input_value},
                    "output": {"value": output_value},
                    "model_name": session.model,
                    "model_provider": session.model_provider,
                    "metadata": {"models_used": session.models[:]},
                },
                # Intentionally no "metrics" key — see comment above.
            }
            self._apply_project_metadata_to_span(session, root_span)
            self._append_span(root_span)

        session.root_span_emitted = True

    def _handle_turn_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Open a step span for this inference cycle (primary step open point)."""
        session = self._get_or_create_session(session_id)
        turn_index = body.get("turn_index")
        if turn_index is not None:
            self._turn_indexes[session_id] = turn_index
        self._start_step(session, turn_index=turn_index)
        log.debug("Pi turn_start for session %s: turn_index=%s", session_id, turn_index)

    def _handle_turn_end(self, session_id: str, body: Dict[str, Any]) -> None:
        """Finalize the active step span (primary step finalization point)."""
        self._finalize_active_step(session_id)
        log.debug("Pi turn_end for session %s: turn_index=%s", session_id, body.get("turn_index"))

    def _handle_message_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Begin tracking an LLM call.

        If no step is active (e.g. ``message_start`` arrived without a preceding
        ``turn_start``), opens a fallback step so tools still have a parent.
        """
        session = self._get_or_create_session(session_id)

        # Ensure a step exists (fallback if turn_start was missed)
        if session_id not in self._active_steps:
            turn_index = self._turn_indexes.get(session_id)
            self._start_step(session, turn_index=turn_index)

        parent_id = self._active_step_parent_id(session)
        span_id = _format_span_id()
        now_ns = monotonic_wall_ns()

        # The extension snapshots `system_prompt` and the pre-call `messages`
        # array (from the pi `context` event) and forwards both on every
        # assistant message_start so we can populate `input.messages` on the
        # LLM span.
        input_messages = _pi_messages_to_llmobs_input(
            body.get("system_prompt", "") or "",
            body.get("messages", []) or [],
        )

        self._pending_llm[session_id] = PendingLLMSpan(
            span_id=span_id,
            parent_id=parent_id,
            start_ns=now_ns,
            input_messages=input_messages,
        )

    def _handle_message_end(self, session_id: str, body: Dict[str, Any]) -> None:
        """Emit an LLM span with token usage and tool calls.

        Also updates the active step's metadata with the assistant response
        content (output text, tool_use_ids, stop_reason, etc.).  The step
        itself is NOT finalized here — it stays open so downstream tool spans
        can parent to it.  ``turn_end`` or ``agent_end`` finalizes it.
        """
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return

        now_ns = monotonic_wall_ns()
        pending = self._pending_llm.pop(session_id, None)

        if pending:
            span_id = pending.span_id
            parent_id = pending.parent_id
            start_ns = pending.start_ns
            input_messages = pending.input_messages
        else:
            span_id = _format_span_id()
            parent_id = self._active_step_parent_id(session)
            start_ns = now_ns
            # Fallback path — message_start was missed, so we have no
            # context-event snapshot. Build a minimal input from system_prompt
            # + messages on this event if present, else leave empty.
            input_messages = _pi_messages_to_llmobs_input(
                body.get("system_prompt", "") or "",
                body.get("messages", []) or [],
            )

        duration = now_ns - start_ns

        model_id = body.get("model_id", "") or body.get("model", "") or session.model
        model_provider = body.get("model_provider", session.model_provider)
        usage = body.get("usage") or {}
        stop_reason = body.get("stop_reason", "")

        # Extract tool calls and output text from the content array
        content = body.get("content", [])
        if content:
            output_text, tool_calls, tool_use_ids, has_thinking = _extract_output_text_and_tool_calls(content)
        else:
            # Fallback for older extension format
            output_text = body.get("output_text", "")
            raw_tool_calls = body.get("tool_calls", [])
            tool_calls = raw_tool_calls
            tool_use_ids = [tc.get("id", "") for tc in raw_tool_calls if tc.get("id")]
            has_thinking = False

        # Update active step metadata
        active = self._active_steps.get(session_id)
        if active:
            active.output_text = output_text
            active.tool_use_ids = tool_use_ids
            active.has_thinking = has_thinking
            active.stop_reason = stop_reason

        # Build input/output messages in LLMObs format
        output_messages: List[Dict[str, Any]] = []
        if output_text:
            output_messages.append({"content": output_text, "role": "assistant"})
        if tool_calls:
            for tc in tool_calls:
                output_messages.append(
                    {
                        "content": json.dumps(tc.get("arguments", {})),
                        "role": "assistant",
                        "tool_calls": [{"name": tc.get("name", ""), "arguments": tc.get("arguments", {})}],
                    }
                )

        # Token metrics
        input_tokens = usage.get("input", 0)
        output_tokens = usage.get("output", 0)
        cache_read = usage.get("cacheRead", 0)
        cache_write = usage.get("cacheWrite", 0)
        total_tokens = usage.get("totalTokens", 0) or (input_tokens + output_tokens + cache_read + cache_write)

        # Cost: prefer provider-reported cost, fall back to model-based estimate
        provider_cost = usage.get("cost")
        cost_metrics: Dict[str, int] = {}
        if _has_provider_cost(provider_cost):
            cost_metrics = cost_from_provider_usage(cast(Dict[str, float], provider_cost))
        else:
            cost_metrics = _compute_pi_cost_metrics(
                model_id=model_id or "",
                model_provider=model_provider or "",
                non_cached_input_tokens=input_tokens,
                cache_write_tokens=cache_write,
                cache_read_tokens=cache_read,
                output_tokens=output_tokens,
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
                "output_tokens": output_tokens,
                "total_tokens": total_tokens,
                "cache_read_input_tokens": cache_read,
                "cache_write_input_tokens": cache_write,
                "non_cached_input_tokens": input_tokens,
                **cost_metrics,
            },
        }
        self._append_span(span)

    def _handle_tool_execution_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Create a pending tool span (equivalent to PreToolUse).

        Parent is set to the active step span so tools nest under the inference
        cycle that requested them.
        """
        session = self._get_or_create_session(session_id)
        tool_name = body.get("tool_name", "unknown_tool")
        tool_call_id = body.get("tool_call_id", tool_name)
        args = body.get("args", "")
        session.tools_used.add(tool_name)

        span_id = _format_span_id()
        parent_id = self._active_step_parent_id(session)
        now_ns = monotonic_wall_ns()

        # Parse args string back to dict for tool_input if possible
        tool_input: Any = args
        if isinstance(tool_input, str):
            try:
                tool_input = json.loads(tool_input)
            except (json.JSONDecodeError, ValueError):
                pass

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

        now_ns = monotonic_wall_ns()
        pending = session.pending_tools.pop(tool_call_id, None)

        if pending:
            span_id = pending.span_id
            parent_id = pending.parent_id
            start_ns = pending.start_ns
            input_value = _to_json_str(pending.tool_input) if pending.tool_input else ""
            actual_tool_name = pending.tool_name
        else:
            span_id = _format_span_id()
            parent_id = self._active_step_parent_id(session)
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
        dd.setdefault("compactions", []).append(
            {
                "trigger": "auto" if body.get("from_extension") else "manual",
            }
        )

    def _handle_session_shutdown(self, session_id: str, body: Dict[str, Any]) -> None:
        """Finalize session (equivalent to SessionEnd)."""
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        # Finalize any open step before closing the session
        self._finalize_active_step(session_id)
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
        "message_start": "_handle_message_start",
        "message_end": "_handle_message_end",
        "tool_execution_start": "_handle_tool_execution_start",
        "tool_execution_end": "_handle_tool_execution_end",
        "session_compact": "_handle_session_compact",
    }

    def _dispatch(self, body: Dict[str, Any]) -> None:
        session_id = body.get("session_id", "")
        event_name = body.get("hook_event_name", "")
        if session_id:
            session = self._get_or_create_session(session_id)
            self._hooks_api._update_session_project_metadata(session, body)
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
