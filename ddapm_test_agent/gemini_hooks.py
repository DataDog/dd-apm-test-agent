"""Gemini CLI hook events -> LLM Observability spans."""

import logging
import os
from collections import defaultdict
from typing import Any
from typing import DefaultDict
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

from aiohttp import web
from aiohttp.web import Request

from ._clock import monotonic_wall_ns
from .claude_cost_tracker import compute_cost_metrics
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

_ML_APP = os.environ.get("DD_GEMINI_ML_APP", "gemini-cli")
_MODEL_PROVIDER = "google"
_MAX_PROMPT_LEN = 8192
_MAX_RESPONSE_LEN = 4096
_MAX_OUTPUT_SUMMARY_LEN = 2048


class ActiveGeminiStep:
    """Tracks one Gemini inference cycle and any tools it requested."""

    def __init__(
        self,
        span_id: str,
        parent_id: str,
        start_ns: int,
        message_index: int,
        span_ref: Dict[str, Any],
    ) -> None:
        self.span_id = span_id
        self.parent_id = parent_id
        self.start_ns = start_ns
        self.message_index = message_index
        self.span_ref = span_ref
        self.output_text = ""
        self.tool_use_ids: List[str] = []
        self.has_thinking = False
        self.stop_reason = ""
        self.llm_count = 0
        self.tool_count = 0


class GeminiHooksAPI:
    """Handler for Gemini CLI command-hook events.

    Gemini CLI sends command hooks directly over HTTP.  Unlike Codex, there is
    no live JSONL file to tail for the normal capture path; unlike Claude, the
    model request/response and token usage are available in the hook payloads.
    """

    def __init__(self, hooks_api: ClaudeHooksAPI) -> None:
        self._hooks_api = hooks_api
        self._raw_events: List[Dict[str, Any]] = []
        self._active_steps: Dict[str, ActiveGeminiStep] = {}
        self._step_indexes: Dict[str, int] = {}
        self._synthetic_tool_use_ids_by_name: DefaultDict[str, DefaultDict[str, List[str]]] = defaultdict(
            lambda: defaultdict(list)
        )

    # ------------------------------------------------------------------
    # Shared-state helpers
    # ------------------------------------------------------------------

    def _get_or_create_session(self, session_id: str) -> SessionState:
        return self._hooks_api._get_or_create_session(session_id)

    def _append_span(self, span: Dict[str, Any]) -> None:
        self._hooks_api._assembled_spans.append(span)

    def _root_ref(self, session: SessionState) -> Optional[Dict[str, Any]]:
        return getattr(session, "_root_span_ref", None)

    def _current_parent_id(self, session: SessionState) -> str:
        active = self._active_steps.get(session.session_id)
        if active:
            return active.span_id
        return str(session.root_span_id)

    def _append_model(self, session: SessionState, model: str) -> None:
        if not model:
            return
        session.model = model
        if not session.models or session.models[-1] != model:
            session.models.append(model)

    def _append_common_tags(self, session: SessionState, source_tag: str) -> List[str]:
        tags = [
            f"ml_app:{_ML_APP}",
            f"session_id:{session.session_id}",
            f"service:{_ML_APP}",
            "env:local",
            source_tag,
            "language:python",
            f"hostname:{_HOSTNAME}",
        ]
        if _USER_HANDLE:
            tags.append(f"user_handle:{_USER_HANDLE}")
        return tags

    # ------------------------------------------------------------------
    # Gemini payload parsing
    # ------------------------------------------------------------------

    def _extract_model(self, body: Dict[str, Any]) -> str:
        for key in ("model", "model_id"):
            val = body.get(key)
            if isinstance(val, str) and val:
                return val
        llm_request = body.get("llm_request")
        if isinstance(llm_request, dict):
            model = llm_request.get("model")
            if isinstance(model, str):
                return model
        return ""

    def _usage_metrics(self, body: Dict[str, Any]) -> Tuple[Dict[str, int], bool]:
        llm_response = body.get("llm_response")
        usage = llm_response.get("usageMetadata") if isinstance(llm_response, dict) else None
        if not isinstance(usage, dict):
            usage = body.get("usageMetadata")
        if not isinstance(usage, dict):
            usage = body.get("usage")
        if not isinstance(usage, dict):
            return {}, False

        input_tokens = _int_value(usage.get("promptTokenCount", usage.get("input", 0)))
        output_tokens = _int_value(usage.get("candidatesTokenCount", usage.get("output", 0)))
        thought_tokens = _int_value(usage.get("thoughtsTokenCount", usage.get("thoughts", 0)))
        cache_read = _int_value(usage.get("cachedContentTokenCount", usage.get("cacheRead", 0)))
        cache_write = _int_value(usage.get("cacheWrite", 0))
        total_tokens = _int_value(usage.get("totalTokenCount", usage.get("totalTokens", 0)))
        if not total_tokens:
            total_tokens = input_tokens + output_tokens + thought_tokens

        non_cached_input = max(input_tokens - cache_read - cache_write, 0)
        metrics = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": total_tokens,
            "cache_read_input_tokens": cache_read,
            "cache_write_input_tokens": cache_write,
            "non_cached_input_tokens": non_cached_input,
        }
        if thought_tokens:
            metrics["reasoning_tokens"] = thought_tokens
            metrics["gemini_thoughts_tokens"] = thought_tokens

        model = self._extract_model(body)
        cost_metrics = compute_cost_metrics(
            model_id=model,
            non_cached_input_tokens=non_cached_input,
            cache_write_tokens=cache_write,
            cache_read_tokens=cache_read,
            output_tokens=output_tokens,
        )
        if cost_metrics:
            metrics.update(cost_metrics)

        return metrics, thought_tokens > 0

    def _llm_input_messages(self, body: Dict[str, Any]) -> List[Dict[str, Any]]:
        llm_request = body.get("llm_request")
        if not isinstance(llm_request, dict):
            return []

        messages: List[Dict[str, Any]] = []
        system_instruction = llm_request.get("systemInstruction")
        system_text = _gemini_content_to_text(system_instruction)
        if system_text:
            messages.append({"role": "system", "content": system_text})

        contents = llm_request.get("contents", [])
        if not isinstance(contents, list):
            contents = []

        for content in contents:
            if not isinstance(content, dict):
                continue
            role = _gemini_role(content.get("role"))
            text, tool_calls, tool_id = _gemini_parts_to_text_and_tools(content.get("parts", []))
            entry: Dict[str, Any] = {"role": role, "content": text}
            if tool_id and role == "tool":
                entry["tool_id"] = tool_id
            if tool_calls:
                entry["tool_calls"] = tool_calls
            messages.append(entry)

        legacy_messages = llm_request.get("messages", [])
        if isinstance(legacy_messages, list):
            for message in legacy_messages:
                if not isinstance(message, dict):
                    continue
                role = _gemini_role(message.get("role"))
                content = message.get("content", "")
                if isinstance(content, list):
                    text, tool_calls, tool_id = _gemini_parts_to_text_and_tools(content)
                else:
                    text, tool_calls, tool_id = _to_json_str(content), [], ""
                entry = {"role": role, "content": text}
                if tool_id and role == "tool":
                    entry["tool_id"] = tool_id
                if tool_calls:
                    entry["tool_calls"] = tool_calls
                messages.append(entry)
        return messages

    def _llm_output(self, body: Dict[str, Any]) -> Tuple[str, List[Dict[str, Any]], List[str], str]:
        llm_response = body.get("llm_response")
        if not isinstance(llm_response, dict):
            return "", [], [], ""

        candidates = llm_response.get("candidates", [])
        if not isinstance(candidates, list):
            return "", [], [], ""

        text_parts: List[str] = []
        tool_calls: List[Dict[str, Any]] = []
        tool_use_ids: List[str] = []
        stop_reason = ""

        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            if not stop_reason and isinstance(candidate.get("finishReason"), str):
                stop_reason = candidate["finishReason"]
            content = candidate.get("content")
            if not isinstance(content, dict):
                continue
            text, calls, _tool_id = _gemini_parts_to_text_and_tools(content.get("parts", []))
            if text:
                text_parts.append(text)
            for call in calls:
                tool_calls.append(call)
                tool_id = str(call.get("tool_id", ""))
                if tool_id:
                    tool_use_ids.append(tool_id)

        return "\n".join(text_parts), tool_calls, tool_use_ids, stop_reason

    # ------------------------------------------------------------------
    # Span lifecycle
    # ------------------------------------------------------------------

    def _clear_turn_state(self, session_id: str) -> None:
        self._active_steps.pop(session_id, None)
        self._step_indexes[session_id] = 0
        self._synthetic_tool_use_ids_by_name.pop(session_id, None)

    def _start_root(self, session: SessionState, prompt: str) -> None:
        if session.root_span_emitted:
            now_ns = monotonic_wall_ns()
            session.trace_id = _format_trace_id()
            session.root_span_id = _format_span_id()
            session.start_ns = now_ns
            session.user_prompts = []
            session.tools_used = set()
            session.pending_tools = {}
            session.agent_span_stack = []
            session.deferred_agent_spans = {}
            session.claimed_task_tools = set()
            session.active_agents = {}
            session.root_span_emitted = False
            session.models = [session.model] if session.model else []
        elif self._root_ref(session) is not None:
            self._finalize_root(session, {"prompt_response": ""}, status="error", error_message="interrupted")

        self._clear_turn_state(session.session_id)

        if prompt:
            session.user_prompts.append(prompt)

        root_span: Dict[str, Any] = {
            "span_id": session.root_span_id,
            "trace_id": session.trace_id,
            "parent_id": "undefined",
            "name": "gemini-request",
            "status": "ok",
            "start_ns": session.start_ns,
            "duration": 0,
            "ml_app": _ML_APP,
            "service": _ML_APP,
            "env": "local",
            "session_id": session.session_id,
            "tags": self._append_common_tags(session, "source:gemini-hooks") + ["trajectory.semantic_type:turn"],
            "meta": {
                "span": {"kind": "agent"},
                "input": {"value": prompt},
                "output": {"value": ""},
                "model_name": session.model,
                "model_provider": session.model_provider or _MODEL_PROVIDER,
                "metadata": {"models_used": session.models[:]},
            },
            "metrics": {},
        }
        self._append_span(root_span)
        session._root_span_ref = root_span  # type: ignore[attr-defined]

    def _start_step(self, session: SessionState) -> ActiveGeminiStep:
        self._finalize_active_step(session.session_id)

        idx = self._step_indexes.get(session.session_id, 0)
        self._step_indexes[session.session_id] = idx + 1
        now_ns = monotonic_wall_ns()
        span_id = _format_span_id()
        parent_id = session.root_span_id

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
            "tags": self._append_common_tags(session, "source:gemini-hooks")
            + ["trajectory.semantic_type:agent_message"],
            "meta": {
                "span": {"kind": "step"},
                "input": {},
                "output": {"value": ""},
                "metadata": {"message_index": idx},
            },
            "metrics": {},
        }
        self._append_span(step_span)

        active = ActiveGeminiStep(
            span_id=span_id,
            parent_id=parent_id,
            start_ns=now_ns,
            message_index=idx,
            span_ref=step_span,
        )
        self._active_steps[session.session_id] = active
        return active

    def _ensure_step(self, session: SessionState, *, new_after_existing_llm: bool = False) -> ActiveGeminiStep:
        active = self._active_steps.get(session.session_id)
        if active is None:
            return self._start_step(session)
        if new_after_existing_llm and active.llm_count > 0:
            return self._start_step(session)
        return active

    def _finalize_active_step(self, session_id: str, end_ns: Optional[int] = None) -> None:
        active = self._active_steps.pop(session_id, None)
        if not active:
            return

        if end_ns is None:
            end_ns = monotonic_wall_ns()

        ref = active.span_ref
        ref["duration"] = end_ns - active.start_ns
        ref["meta"]["output"]["value"] = active.output_text
        metadata = ref["meta"].setdefault("metadata", {})
        metadata["message_index"] = active.message_index
        if active.tool_use_ids:
            metadata["tool_use_ids"] = active.tool_use_ids
        if active.has_thinking:
            metadata["has_thinking"] = True
        if active.stop_reason:
            metadata["stop_reason"] = active.stop_reason

    def _finalize_root(
        self,
        session: SessionState,
        body: Dict[str, Any],
        *,
        status: str = "ok",
        error_message: str = "",
    ) -> None:
        self._finalize_active_step(session.session_id)

        root_span = self._root_ref(session)
        if not root_span:
            return

        now_ns = monotonic_wall_ns()
        output_value = str(body.get("prompt_response", body.get("output", "")) or "")
        if len(output_value) > _MAX_RESPONSE_LEN:
            output_value = output_value[:_MAX_RESPONSE_LEN]

        root_span["duration"] = now_ns - session.start_ns
        root_span["status"] = status
        root_span["meta"]["input"]["value"] = "\n\n".join(session.user_prompts)
        root_span["meta"]["output"]["value"] = output_value
        root_span["meta"]["model_name"] = session.model
        root_span["meta"]["model_provider"] = session.model_provider or _MODEL_PROVIDER
        root_span["meta"].setdefault("metadata", {})["models_used"] = session.models[:]
        if error_message:
            root_span["meta"]["error"] = {"message": error_message}

        tool_usage = self._hooks_api._aggregate_tool_usage(session.trace_id)
        dd_fields: Dict[str, Any] = {
            "agent_manifest": {
                "name": _ML_APP,
                "model": session.model,
                "model_provider": session.model_provider or _MODEL_PROVIDER,
                "models": session.models[:],
                "tools": [{"name": name} for name in sorted(session.tools_used)],
            }
        }
        if tool_usage:
            dd_fields["tool_usage"] = tool_usage
        self._hooks_api._set_hidden_metadata(root_span, **dd_fields)

        session.root_span_emitted = True

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def _handle_session_start(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        session.model_provider = _MODEL_PROVIDER
        self._append_model(session, self._extract_model(body))
        log.info("Gemini session started: %s (model=%s)", session_id, session.model)

    def _handle_before_agent(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._get_or_create_session(session_id)
        session.model_provider = _MODEL_PROVIDER
        self._append_model(session, self._extract_model(body))

        prompt = str(body.get("prompt", body.get("user_prompt", "")) or "")
        if len(prompt) > _MAX_PROMPT_LEN:
            prompt = prompt[:_MAX_PROMPT_LEN]
        self._start_root(session, prompt)

    def _handle_after_model(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session or not self._root_ref(session):
            return

        model = self._extract_model(body)
        self._append_model(session, model)
        session.model_provider = _MODEL_PROVIDER

        active = self._ensure_step(session, new_after_existing_llm=True)
        input_messages = self._llm_input_messages(body)
        output_text, tool_calls, tool_use_ids, stop_reason = self._llm_output(body)
        metrics, has_thinking = self._usage_metrics(body)

        if output_text:
            active.output_text = output_text
        if tool_use_ids:
            active.tool_use_ids = tool_use_ids
        if has_thinking:
            active.has_thinking = True
        if stop_reason:
            active.stop_reason = stop_reason

        output_messages: List[Dict[str, Any]] = []
        if output_text or tool_calls:
            message: Dict[str, Any] = {"role": "assistant", "content": output_text}
            if tool_calls:
                message["tool_calls"] = tool_calls
            output_messages.append(message)

        now_ns = monotonic_wall_ns()
        span = {
            "span_id": _format_span_id(),
            "trace_id": session.trace_id,
            "parent_id": active.span_id,
            "name": model or session.model or "gemini",
            "status": "ok",
            "start_ns": now_ns,
            "duration": 1,
            "ml_app": _ML_APP,
            "service": _ML_APP,
            "env": "local",
            "session_id": session.session_id,
            "tags": self._append_common_tags(session, "source:gemini-hooks"),
            "meta": {
                "span": {"kind": "llm"},
                "model_name": model or session.model,
                "model_provider": _MODEL_PROVIDER,
                "input": {"messages": input_messages},
                "output": {"messages": output_messages},
                "metadata": {"stop_reason": stop_reason},
            },
            "metrics": metrics,
        }
        self._append_span(span)
        active.llm_count += 1

    def _handle_before_tool(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session or not self._root_ref(session):
            return

        active = self._ensure_step(session)
        tool_name = str(body.get("tool_name", "unknown_tool") or "unknown_tool")
        tool_use_id = _extract_tool_use_id(body)
        if not tool_use_id:
            tool_use_id = _synthetic_tool_use_id(session_id, tool_name, len(session.pending_tools))
            self._synthetic_tool_use_ids_by_name[session_id][tool_name].append(tool_use_id)

        tool_input = body.get("tool_input")
        if tool_input is None:
            tool_input = {}

        session.tools_used.add(tool_name)
        span_id = _format_span_id()
        session.pending_tools[tool_use_id] = PendingToolSpan(
            span_id=span_id,
            tool_name=tool_name,
            tool_input=tool_input,
            parent_id=active.span_id,
            start_ns=monotonic_wall_ns(),
        )

    def _handle_after_tool(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session or not self._root_ref(session):
            return

        active = self._ensure_step(session)
        tool_name = str(body.get("tool_name", "unknown_tool") or "unknown_tool")
        tool_use_id = _extract_tool_use_id(body)
        if not tool_use_id:
            tool_use_id = self._pop_synthetic_tool_use_id(session_id, tool_name)
        if not tool_use_id:
            tool_use_id = _synthetic_tool_use_id(session_id, tool_name, len(session.pending_tools))

        now_ns = monotonic_wall_ns()
        pending = session.pending_tools.pop(tool_use_id, None)
        if pending:
            span_id = pending.span_id
            parent_id = pending.parent_id
            start_ns = pending.start_ns
            input_value = _to_json_str(pending.tool_input) if pending.tool_input else ""
            actual_tool_name = pending.tool_name
        else:
            span_id = _format_span_id()
            parent_id = active.span_id
            start_ns = now_ns
            input_value = ""
            actual_tool_name = tool_name

        session.tools_used.add(actual_tool_name)
        active.tool_count += 1
        if tool_use_id not in active.tool_use_ids:
            active.tool_use_ids.append(tool_use_id)

        tool_error = str(body.get("tool_error", "") or "")
        is_error = bool(tool_error)
        output = body.get("tool_response", "")
        output_value = _to_json_str(output) if output != "" else ""
        if len(output_value) > _MAX_OUTPUT_SUMMARY_LEN:
            output_value = output_value[:_MAX_OUTPUT_SUMMARY_LEN]
        if is_error and len(tool_error) > _MAX_OUTPUT_SUMMARY_LEN:
            tool_error = tool_error[:_MAX_OUTPUT_SUMMARY_LEN]

        span: Dict[str, Any] = {
            "span_id": span_id,
            "trace_id": session.trace_id,
            "parent_id": parent_id,
            "name": actual_tool_name,
            "status": "error" if is_error else "ok",
            "start_ns": start_ns,
            "duration": now_ns - start_ns,
            "ml_app": _ML_APP,
            "service": _ML_APP,
            "env": "local",
            "session_id": session.session_id,
            "tags": self._append_common_tags(session, "source:gemini-hooks") + [f"tool_name:{actual_tool_name}"],
            "meta": {
                "span": {"kind": "tool"},
                "input": {"value": input_value},
                "output": {"value": output_value},
                "model_name": session.model,
                "model_provider": _MODEL_PROVIDER,
                "metadata": {"tool_id": tool_use_id},
            },
            "metrics": {},
        }
        if is_error:
            span["meta"]["error"] = {"message": tool_error or output_value}

        if session.pending_permission_at_ns is not None:
            wait_ms = (now_ns - session.pending_permission_at_ns) // 1_000_000
            session.pending_permission_at_ns = None
            self._hooks_api._set_hidden_metadata(span, estimated_permission_wait_ms=wait_ms)
            self._hooks_api._set_permission_wait_critical_evaluation(span, wait_ms)

        self._append_span(span)

    def _pop_synthetic_tool_use_id(self, session_id: str, tool_name: str) -> str:
        by_name = self._synthetic_tool_use_ids_by_name.get(session_id)
        if not by_name:
            return ""

        pending_for_name = by_name.get(tool_name)
        if pending_for_name:
            tool_use_id = pending_for_name.pop(0)
            if not pending_for_name:
                by_name.pop(tool_name, None)
            return tool_use_id

        for name, pending_ids in list(by_name.items()):
            if pending_ids:
                tool_use_id = pending_ids.pop(0)
                if not pending_ids:
                    by_name.pop(name, None)
                return tool_use_id
        return ""

    def _handle_after_agent(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        self._finalize_root(session, body)

    def _handle_session_end(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        if not session.root_span_emitted and self._root_ref(session):
            self._finalize_root(session, body, status="error", error_message=str(body.get("reason", "session ended")))
        self._clear_turn_state(session_id)

    def _handle_pre_compress(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        active = self._active_steps.get(session_id)
        span_ref = active.span_ref if active else self._root_ref(session)
        if span_ref is None:
            return
        dd = span_ref.setdefault("meta", {}).setdefault("metadata", {}).setdefault("_dd", {})
        dd.setdefault("compactions", []).append(
            {
                "trigger": body.get("trigger", ""),
                "transcript_path": body.get("transcript_path", ""),
            }
        )

    def _handle_notification(self, session_id: str, body: Dict[str, Any]) -> None:
        session = self._hooks_api._sessions.get(session_id)
        if not session:
            return
        notification_type = str(body.get("notification_type", "") or "").lower()
        if "permission" in notification_type or "tool" in notification_type:
            session.pending_permission_at_ns = monotonic_wall_ns()

    _HANDLERS: Dict[str, str] = {
        "SessionStart": "_handle_session_start",
        "SessionEnd": "_handle_session_end",
        "BeforeAgent": "_handle_before_agent",
        "AfterAgent": "_handle_after_agent",
        "AfterModel": "_handle_after_model",
        "BeforeTool": "_handle_before_tool",
        "AfterTool": "_handle_after_tool",
        "PreCompress": "_handle_pre_compress",
        "Notification": "_handle_notification",
    }

    def _dispatch(self, event_type: str, body: Dict[str, Any]) -> None:
        session_id = str(body.get("session_id", "") or "")
        handler_name = self._HANDLERS.get(event_type)
        if handler_name:
            handler = getattr(self, handler_name)
            handler(session_id, body)
        else:
            log.debug("Unhandled Gemini hook event: %s", event_type)

    # ------------------------------------------------------------------
    # HTTP handlers
    # ------------------------------------------------------------------

    async def handle_hook(self, request: Request) -> web.Response:
        """Handle Gemini hook payloads.

        Supports both ``POST /gemini/hooks/{event_type}`` and
        ``POST /gemini/hooks`` with ``hook_event_name`` in the JSON body.
        """
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)

        event_type = request.match_info.get("event_type") or body.get("hook_event_name") or body.get("event_type")
        if not isinstance(event_type, str) or not event_type:
            return web.json_response({"error": "missing event_type"}, status=400)
        if event_type not in self._HANDLERS:
            return web.json_response({"error": f"unknown event_type: {event_type}"}, status=400)

        session_id = body.get("session_id", "")
        if not session_id:
            return web.json_response({"error": "missing session_id"}, status=400)

        body["hook_event_name"] = event_type
        self._raw_events.append(body)
        self._dispatch(event_type, body)

        if event_type in ("AfterAgent", "SessionEnd"):
            await self._hooks_api._forward_trace_to_backend(str(session_id))
            await self._hooks_api._forward_eval_metrics_to_backend(str(session_id))

        return web.json_response({"status": "ok"})

    async def handle_raw_events(self, request: Request) -> web.Response:
        """Handle GET /gemini/hooks/raw."""
        return web.json_response({"events": self._raw_events})

    async def handle_sessions(self, request: Request) -> web.Response:
        """Handle GET /gemini/hooks/sessions."""
        sessions = []
        for sid, state in self._hooks_api._sessions.items():
            sessions.append(
                {
                    "session_id": sid,
                    "trace_id": state.trace_id,
                    "root_span_id": state.root_span_id,
                    "num_prompts": len(state.user_prompts),
                    "pending_tools": len(state.pending_tools),
                    "active_step": sid in self._active_steps,
                    "models": state.models,
                }
            )
        return web.json_response({"sessions": sessions})

    async def handle_spans(self, request: Request) -> web.Response:
        """Handle GET /gemini/hooks/spans."""
        return web.json_response({"spans": self._hooks_api._assembled_spans})

    def get_routes(self) -> List[web.RouteDef]:
        """Return Gemini hook routes."""
        return [
            web.post("/gemini/hooks", with_cors(self.handle_hook)),
            web.post("/gemini/hooks/{event_type}", with_cors(self.handle_hook)),
            web.post("/capture/gemini/{event_type}", with_cors(self.handle_hook)),
            web.route("*", "/gemini/hooks/raw", with_cors(self.handle_raw_events)),
            web.route("*", "/gemini/hooks/sessions", with_cors(self.handle_sessions)),
            web.route("*", "/gemini/hooks/spans", with_cors(self.handle_spans)),
        ]


def _int_value(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value))
        except ValueError:
            return 0
    return 0


def _gemini_role(role: Any) -> str:
    if role == "model":
        return "assistant"
    if role == "function":
        return "tool"
    if isinstance(role, str) and role:
        return role
    return "user"


def _gemini_content_to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        text, _tool_calls, _tool_id = _gemini_parts_to_text_and_tools(value.get("parts", []))
        return text
    return ""


def _gemini_parts_to_text_and_tools(parts: Any) -> Tuple[str, List[Dict[str, Any]], str]:
    if not isinstance(parts, list):
        return "", [], ""

    text_parts: List[str] = []
    tool_calls: List[Dict[str, Any]] = []
    tool_id = ""

    for part in parts:
        if isinstance(part, str):
            if part:
                text_parts.append(part)
            continue
        if not isinstance(part, dict):
            continue
        text = part.get("text")
        if isinstance(text, str) and text:
            text_parts.append(text)
            continue

        function_call = part.get("functionCall")
        if isinstance(function_call, dict):
            name = str(function_call.get("name", "") or "")
            args = function_call.get("args")
            if not isinstance(args, dict):
                args = {}
            call_id = str(function_call.get("id", "") or "")
            if not call_id:
                call_id = _synthetic_tool_use_id("gemini", name, len(tool_calls))
            tool_calls.append({"name": name, "arguments": args, "tool_id": call_id, "type": "tool_use"})
            continue

        function_response = part.get("functionResponse")
        if isinstance(function_response, dict):
            tool_id = str(function_response.get("id", "") or "")
            response = function_response.get("response")
            if response is not None:
                text_parts.append(_to_json_str(response))

    return "\n".join(text_parts), tool_calls, tool_id


def _extract_tool_use_id(body: Dict[str, Any]) -> str:
    for key in ("tool_use_id", "tool_call_id", "id"):
        value = body.get(key)
        if isinstance(value, str) and value:
            return value
    mcp_context = body.get("mcp_context")
    if isinstance(mcp_context, dict):
        value = mcp_context.get("tool_use_id")
        if isinstance(value, str) and value:
            return value
    return ""


def _synthetic_tool_use_id(session_id: str, tool_name: str, index: int) -> str:
    safe_tool = tool_name.replace(" ", "_") or "tool"
    return f"gemini-{session_id}-{safe_tool}-{index}"
