"""Codex session JSONL -> LLM Observability spans."""

import datetime
import json
import logging
import os
import socket
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set
from typing import Tuple

from aiohttp import web
from aiohttp.web import Request

from .claude_hooks import ClaudeHooksAPI
from .claude_hooks import PendingToolSpan
from .claude_hooks import SessionState
from .claude_hooks import _format_span_id
from .claude_hooks import _format_trace_id
from .claude_hooks import _to_json_str
from .codex_cost_tracker import compute_openai_cost_metrics
from .llmobs_event_platform import with_cors


log = logging.getLogger(__name__)

CompletedTrace = Tuple[str, str]
OrphanProxySpan = Tuple[Optional[str], Dict[str, Any]]


def _timestamp_to_ns(timestamp: str) -> int:
    if not timestamp:
        return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1_000_000_000)
    try:
        dt = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return int(dt.timestamp() * 1_000_000_000)
    except ValueError:
        return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1_000_000_000)


def _content_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: List[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if item.get("type") in ("input_text", "output_text"):
            text = item.get("text", "")
            if text:
                parts.append(str(text))
    return "\n\n".join(parts)


def _copy_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [dict(message) for message in messages]


def _append_unique_message(messages: List[Dict[str, Any]], message: Dict[str, Any]) -> None:
    if message not in messages:
        messages.append(message)


def _append_or_update_tool_call_message(messages: List[Dict[str, Any]], message: Dict[str, Any]) -> None:
    tool_calls = message.get("tool_calls", [])
    if not tool_calls:
        _append_unique_message(messages, message)
        return

    call_id = tool_calls[0].get("id", "")
    for existing in messages:
        existing_tool_calls = existing.get("tool_calls", [])
        if not isinstance(existing_tool_calls, list):
            continue
        for existing_tool_call in existing_tool_calls:
            if isinstance(existing_tool_call, dict) and existing_tool_call.get("id") == call_id:
                incoming_tool_call = tool_calls[0]
                if not existing_tool_call.get("arguments") and incoming_tool_call.get("arguments") is not None:
                    existing_tool_call["arguments"] = incoming_tool_call.get("arguments")
                if not existing_tool_call.get("name") and incoming_tool_call.get("name"):
                    existing_tool_call["name"] = incoming_tool_call.get("name")
                if not existing.get("content") and message.get("content"):
                    existing["content"] = message["content"]
                return
    messages.append(message)


def _is_assistant_tool_call_message(message: Dict[str, Any]) -> bool:
    return message.get("role") == "assistant" and bool(message.get("tool_calls"))


def _has_llm_output(messages: List[Dict[str, Any]]) -> bool:
    return any(message.get("content") or message.get("tool_calls") for message in messages)


def _llm_has_text_output(span: Optional[Dict[str, Any]], message: str) -> bool:
    if span is None:
        return False
    output_messages = span.get("meta", {}).get("output", {}).get("messages", [])
    if not isinstance(output_messages, list):
        return False
    return any(output.get("role") == "assistant" and output.get("content") == message for output in output_messages)


def _normalized_text(value: Any) -> str:
    return " ".join(str(value).split())


class CodexTurn:
    def __init__(self, turn_id: str, trace_id: str, root_span_id: str, step_span_id: str, start_ns: int) -> None:
        self.turn_id = turn_id
        self.trace_id = trace_id
        self.root_span_id = root_span_id
        self.step_span_id = step_span_id
        self.start_ns = start_ns
        self.root_span_ref: Optional[Dict[str, Any]] = None
        self.step_span_ref: Optional[Dict[str, Any]] = None
        self.step_span_refs: Dict[str, Dict[str, Any]] = {}
        self.step_count = 0
        self.current_step_start_ns: Optional[int] = None
        self.current_step_last_ns: Optional[int] = None
        self.current_step_has_llm = False
        self.llm_start_ns: Optional[int] = None
        self.llm_input_messages: List[Dict[str, Any]] = []
        self.active_llm_input_messages: Optional[List[Dict[str, Any]]] = None
        self.llm_output_messages: List[Dict[str, Any]] = []
        self.pending_llm_input_messages: List[Dict[str, Any]] = []
        self.pending_llm_usage: Optional[Dict[str, Any]] = None
        self.pending_llm_end_ns: Optional[int] = None
        self.last_step_span_ref: Optional[Dict[str, Any]] = None
        self.last_llm_span_ref: Optional[Dict[str, Any]] = None
        self.last_ns = start_ns
        self.closed = False
        self.proxy_llm_calls_started = 0
        self.proxy_llm_spans_completed = 0
        self.proxy_llm_usage_events_seen = 0


class CodexSession:
    def __init__(self, session_id: str, start_ns: int) -> None:
        self.session_id = session_id
        self.start_ns = start_ns
        self.cwd = ""
        self.originator = ""
        self.cli_version = ""
        self.model_provider = "openai"
        self.model = ""
        self.effort = ""
        self.user_prompts: List[str] = []
        self.tools_used: Set[str] = set()
        self.pending_tools: Dict[str, PendingToolSpan] = {}
        self.active_turn: Optional[CodexTurn] = None
        self.completed_turns: List[str] = []
        self.seen_records: Set[str] = set()
        # Codex reuses tool call_ids like "web_search_2" across turns. Track
        # how many times each id has been seen and the unique id currently in
        # flight so PendingToolSpan keys stay unique and outputs pair correctly.
        self.seen_tool_use_ids: Dict[str, int] = {}
        self.tool_use_id_map: Dict[str, str] = {}
        # Subagent (collab_agent_spawn) stack — mirrors the Claude agent_span_stack
        # pattern so spans emitted while a subagent is active nest beneath it.
        self.agent_span_stack: List[Dict[str, Any]] = []
        self.pending_subagents: Dict[str, Dict[str, Any]] = {}


class CodexConfig:
    def __init__(self) -> None:
        self.ml_app = os.environ.get("DD_CODEX_ML_APP", "codex")
        self.service = self.ml_app
        self.env = "local"
        self.agent_name = self.ml_app
        self.hostname = socket.gethostname()
        self.user_handle = os.environ.get("DD_USER_HANDLE", "")


class CodexHooksAPI:
    """Handler for Codex session JSONL records.

    Codex already writes a structured session JSONL. Lapdog tails those files
    and posts each record here, wrapped with the Codex session id.
    """

    def __init__(self, hooks_api: ClaudeHooksAPI) -> None:
        self._hooks_api = hooks_api
        self._config = CodexConfig()
        self._sessions: Dict[str, CodexSession] = {}
        self._raw_events: List[Dict[str, Any]] = []
        self._last_session_id = ""
        self._proxy_session_ids: Dict[str, str] = {}
        self._orphan_proxy_llm_spans: List[OrphanProxySpan] = []

    def _append_span(self, span: Dict[str, Any]) -> None:
        self._hooks_api._assembled_spans.append(span)

    def _get_or_create_session(self, session_id: str, start_ns: int) -> CodexSession:
        if session_id not in self._sessions:
            self._sessions[session_id] = CodexSession(session_id=session_id, start_ns=start_ns)
            if session_id not in self._hooks_api._sessions:
                self._hooks_api._sessions[session_id] = SessionState(
                    session_id=session_id,
                    trace_id=_format_trace_id(),
                    root_span_id=_format_span_id(),
                    start_ns=start_ns,
                )
        return self._sessions[session_id]

    def _base_tags(self, session: CodexSession, source: str = "codex-jsonl") -> List[str]:
        tags = [
            f"ml_app:{self._config.ml_app}",
            f"session_id:{session.session_id}",
            f"service:{self._config.service}",
            f"env:{self._config.env}",
            f"source:{source}",
            "language:python",
            f"hostname:{self._config.hostname}",
        ]
        if self._config.user_handle:
            tags.append(f"user_handle:{self._config.user_handle}")
        return tags

    def _agent_manifest(self, session: CodexSession) -> Dict[str, Any]:
        model_settings: Dict[str, Any] = {}
        if session.effort:
            model_settings["reasoning_effort"] = session.effort
        return {
            "name": self._config.agent_name,
            "instructions": "",
            "handoff_description": "",
            "model": session.model,
            "model_provider": session.model_provider,
            "model_settings": model_settings,
            "tools": [{"name": name} for name in sorted(session.tools_used)],
            "handoffs": [],
            "guardrails": [],
        }

    def _update_agent_manifest(self, session: CodexSession) -> None:
        turn = session.active_turn
        if turn is None or not turn.root_span_ref:
            return
        metadata = turn.root_span_ref["meta"].setdefault("metadata", {})
        dd_metadata = metadata.setdefault("_dd", {})
        dd_metadata["agent_manifest"] = self._agent_manifest(session)

    def _llm_input_messages(self, session: CodexSession, turn: CodexTurn) -> List[Dict[str, Any]]:
        if turn.llm_input_messages:
            return _copy_messages(turn.llm_input_messages)
        prompt = "\n\n".join(session.user_prompts)
        if prompt:
            return [{"role": "user", "content": prompt}]
        return []

    def _llm_input_value(self, session: CodexSession, turn: CodexTurn) -> str:
        messages = [
            message
            for message in self._llm_input_messages(session, turn)
            if not _is_assistant_tool_call_message(message)
        ]
        if not messages:
            return ""
        if len(messages) == 1 and messages[0].get("role") == "user":
            return str(messages[0].get("content", ""))
        return _to_json_str(messages)

    def _proxy_span_user_inputs(self, span: Dict[str, Any]) -> Set[str]:
        messages = span.get("meta", {}).get("input", {}).get("messages", [])
        if not isinstance(messages, list):
            return set()
        values: Set[str] = set()
        for message in messages:
            if not isinstance(message, dict):
                continue
            if message.get("role") not in ("user", None):
                continue
            text = _normalized_text(message.get("content", ""))
            if text:
                values.add(text)
        return values

    def _session_user_inputs(self, session: CodexSession) -> Set[str]:
        values = {_normalized_text(prompt) for prompt in session.user_prompts if _normalized_text(prompt)}
        joined_prompts = _normalized_text("\n\n".join(session.user_prompts))
        if joined_prompts:
            values.add(joined_prompts)
        turn = session.active_turn
        if turn is not None:
            for message in turn.llm_input_messages:
                if message.get("role") != "user":
                    continue
                text = _normalized_text(message.get("content", ""))
                if text:
                    values.add(text)
        return values

    def _proxy_span_matches_session(self, span: Dict[str, Any], session: CodexSession) -> bool:
        proxy_inputs = self._proxy_span_user_inputs(span)
        if not proxy_inputs:
            return False
        return bool(proxy_inputs & self._session_user_inputs(session))

    def _matching_proxy_span_session(
        self, proxy_session_key: Optional[str], span: Dict[str, Any]
    ) -> Optional[CodexSession]:
        if not proxy_session_key:
            return None
        for session in reversed(list(self._sessions.values())):
            turn = session.active_turn
            if turn is None or turn.closed:
                continue
            if self._proxy_span_matches_session(span, session):
                self._proxy_session_ids[proxy_session_key] = session.session_id
                return session
        return None

    def _set_step_input(self, session: CodexSession, turn: CodexTurn, step: Dict[str, Any]) -> None:
        input_value = self._llm_input_value(session, turn)
        if input_value:
            step["meta"]["input"]["value"] = input_value

    def _mark_llm_start(self, session: CodexSession, turn: CodexTurn, start_ns: int) -> None:
        if turn.llm_start_ns is None:
            turn.llm_start_ns = start_ns
        if turn.active_llm_input_messages is None:
            turn.active_llm_input_messages = self._llm_input_messages(session, turn)

    def _begin_llm_in_step(self, session: CodexSession, turn: CodexTurn, start_ns: int) -> None:
        if turn.step_span_ref is not None and turn.current_step_has_llm and not session.pending_tools:
            self._close_current_step(turn)
        self._ensure_step(session, turn, start_ns)
        self._mark_llm_start(session, turn, start_ns)

    def _set_step_output(self, turn: CodexTurn, message: str) -> None:
        if not message:
            return
        step = turn.step_span_ref or turn.last_step_span_ref
        if step is not None:
            step["meta"]["output"]["value"] = message

    def _set_llm_output(self, turn: CodexTurn, message: str) -> None:
        if not message:
            return
        output_message = {"role": "assistant", "content": message}
        if turn.llm_start_ns is not None and not turn.current_step_has_llm:
            _append_unique_message(turn.llm_output_messages, output_message)
        if turn.last_llm_span_ref is not None and not turn.last_llm_span_ref["meta"]["output"].get("messages"):
            turn.last_llm_span_ref["meta"]["output"]["messages"] = [dict(output_message)]

    def _append_llm_span(self, turn: CodexTurn, span: Dict[str, Any]) -> None:
        insert_at: Optional[int] = None
        for index, existing in enumerate(self._hooks_api._assembled_spans):
            if existing.get("parent_id") != span["parent_id"]:
                continue
            if existing.get("meta", {}).get("span", {}).get("kind") != "tool":
                continue
            if existing.get("start_ns", 0) >= span["start_ns"]:
                insert_at = index
                break
        if insert_at is None:
            self._append_span(span)
        else:
            self._hooks_api._assembled_spans.insert(insert_at, span)
        turn.last_llm_span_ref = span

    def _start_turn(self, session: CodexSession, record: Dict[str, Any]) -> List[CompletedTrace]:
        completed = self._finalize_turn(session, status="ok")

        payload = record.get("payload", {})
        timestamp_ns = _timestamp_to_ns(record.get("timestamp", ""))
        turn_id = payload.get("turn_id") or _format_span_id()
        session.cwd = payload.get("cwd", session.cwd)
        session.model = payload.get("model", session.model)
        session.effort = payload.get("effort", session.effort)
        trace_id = _format_trace_id()
        root_span_id = _format_span_id()
        shared_session = self._hooks_api._sessions.get(session.session_id)
        if shared_session is not None:
            shared_session.trace_id = trace_id
            shared_session.root_span_id = root_span_id
            shared_session.start_ns = timestamp_ns

        turn = CodexTurn(
            turn_id=turn_id,
            trace_id=trace_id,
            root_span_id=root_span_id,
            step_span_id="",
            start_ns=timestamp_ns,
        )
        session.active_turn = turn
        session.user_prompts = []
        session.tools_used = set()
        session.pending_tools = {}
        session.tool_use_id_map = {}
        session.agent_span_stack = []
        session.pending_subagents = {}

        root_tags = self._base_tags(session) + ["trajectory.semantic_type:turn"]
        root_span: Dict[str, Any] = {
            "span_id": root_span_id,
            "trace_id": trace_id,
            "parent_id": "undefined",
            "name": "codex-request",
            "status": "ok",
            "start_ns": timestamp_ns,
            "duration": 0,
            "ml_app": self._config.ml_app,
            "service": self._config.service,
            "env": self._config.env,
            "session_id": session.session_id,
            "tags": root_tags,
            "meta": {
                "span": {"kind": "agent"},
                "input": {"value": ""},
                "output": {"value": ""},
                "model_name": session.model,
                "model_provider": session.model_provider,
                "metadata": {
                    "turn_id": turn_id,
                    "cwd": session.cwd,
                    "reasoning_effort": session.effort,
                    "codex_cli_version": session.cli_version,
                    "_dd": {"agent_manifest": self._agent_manifest(session)},
                },
            },
            "metrics": {},
        }
        self._append_span(root_span)
        turn.root_span_ref = root_span
        self._adopt_orphan_proxy_llm_spans(session, turn)
        return completed

    def _ensure_step(self, session: CodexSession, turn: CodexTurn, start_ns: int) -> Dict[str, Any]:
        if turn.step_span_ref is not None:
            return turn.step_span_ref

        step_span_id = _format_span_id()
        turn.step_span_id = step_span_id
        turn.current_step_start_ns = start_ns
        turn.current_step_last_ns = start_ns
        turn.current_step_has_llm = False
        step_tags = self._base_tags(session) + ["trajectory.semantic_type:agent_message"]
        step_span: Dict[str, Any] = {
            "span_id": step_span_id,
            "trace_id": turn.trace_id,
            "parent_id": turn.root_span_id,
            "name": f"inference-{turn.step_count}",
            "status": "ok",
            "start_ns": start_ns,
            "duration": 0,
            "ml_app": self._config.ml_app,
            "service": self._config.service,
            "env": self._config.env,
            "session_id": session.session_id,
            "tags": step_tags,
            "meta": {
                "span": {"kind": "step"},
                "input": {},
                "output": {"value": ""},
                "metadata": {"turn_id": turn.turn_id, "message_index": turn.step_count},
            },
            "metrics": {},
        }
        self._set_step_input(session, turn, step_span)
        self._append_span(step_span)
        turn.step_span_ref = step_span
        turn.step_span_refs[step_span_id] = step_span
        turn.step_count += 1
        return step_span

    def _update_step_end(self, turn: CodexTurn, step_span_id: str, end_ns: int) -> None:
        step = turn.step_span_refs.get(step_span_id)
        if not step:
            return
        step["duration"] = max(end_ns - step["start_ns"], step.get("duration", 0))
        if step is turn.step_span_ref:
            turn.current_step_last_ns = max(turn.current_step_last_ns or end_ns, end_ns)

    def _close_current_step(self, turn: CodexTurn, end_ns: Optional[int] = None) -> None:
        step = turn.step_span_ref
        if step is None:
            return
        if end_ns is None:
            end_ns = turn.current_step_last_ns or turn.last_ns
        step["duration"] = max(end_ns - step["start_ns"], step.get("duration", 0))
        turn.last_step_span_ref = step
        turn.step_span_ref = None
        turn.step_span_id = ""
        turn.current_step_start_ns = None
        turn.current_step_last_ns = None
        turn.current_step_has_llm = False
        turn.llm_start_ns = None
        turn.active_llm_input_messages = None
        turn.llm_output_messages = []
        turn.pending_llm_usage = None
        turn.pending_llm_end_ns = None

    def _begin_llm_call(self, session: CodexSession, record: Dict[str, Any]) -> None:
        turn = self._active_turn(session, record)
        ns = _timestamp_to_ns(record.get("timestamp", ""))
        self._begin_llm_in_step(session, turn, ns)
        turn.last_ns = max(turn.last_ns, ns)

    def _finalize_turn(
        self, session: CodexSession, status: str = "ok", end_ns: Optional[int] = None
    ) -> List[CompletedTrace]:
        turn = session.active_turn
        if turn is None or turn.closed:
            return []
        if end_ns is None:
            end_ns = turn.last_ns
        duration = max(end_ns - turn.start_ns, 0)
        if turn.root_span_ref:
            turn.root_span_ref["duration"] = duration
            turn.root_span_ref["status"] = status
            turn.root_span_ref["meta"]["input"]["value"] = "\n\n".join(session.user_prompts)
            turn.root_span_ref["meta"]["metadata"]["tools"] = sorted(session.tools_used)
            self._update_agent_manifest(session)
        self._emit_pending_llm_span(session, turn)
        for pending in list(session.pending_tools.values()):
            self._emit_tool_span(session, pending, end_ns, output_value="", is_error=True)
        session.pending_tools.clear()
        session.tool_use_id_map.clear()
        # Any subagent that never received a spawn_end is finalized here so its
        # span has a non-zero duration rather than hanging open.
        for entry in session.agent_span_stack:
            span = entry.get("_span_ref")
            if isinstance(span, dict):
                span["duration"] = max(end_ns - int(span.get("start_ns", end_ns)), 0)
                span.setdefault("status", "error")
                span["meta"].setdefault("metadata", {}).setdefault("subagent", {})["status"] = "unterminated"
        session.agent_span_stack.clear()
        session.pending_subagents.clear()
        self._close_current_step(turn, end_ns=turn.current_step_last_ns or end_ns)
        turn.closed = True
        session.completed_turns.append(turn.turn_id)
        return [(session.session_id, turn.trace_id)]

    def _active_turn(self, session: CodexSession, record: Dict[str, Any]) -> CodexTurn:
        if session.active_turn is None or session.active_turn.closed:
            self._start_turn(session, record)
        assert session.active_turn is not None
        return session.active_turn

    def _update_last_ns(self, session: CodexSession, record: Dict[str, Any]) -> int:
        ns = _timestamp_to_ns(record.get("timestamp", ""))
        turn = session.active_turn
        if turn is not None:
            turn.last_ns = max(turn.last_ns, ns)
            duration = max(turn.last_ns - turn.start_ns, 0)
            if turn.root_span_ref:
                turn.root_span_ref["duration"] = duration
            if turn.step_span_ref and turn.current_step_last_ns is not None:
                if not turn.current_step_has_llm or session.pending_tools:
                    self._update_step_end(turn, turn.step_span_ref["span_id"], ns)
        return ns

    def _handle_session_meta(self, session: CodexSession, record: Dict[str, Any]) -> None:
        payload = record.get("payload", {})
        session.cwd = payload.get("cwd", session.cwd)
        session.originator = payload.get("originator", session.originator)
        session.cli_version = payload.get("cli_version", session.cli_version)
        session.model_provider = payload.get("model_provider", session.model_provider) or "openai"

    def _handle_event_msg(self, session: CodexSession, record: Dict[str, Any]) -> List[CompletedTrace]:
        event = record.get("payload", {})
        event_type = event.get("type", "")

        if event_type == "token_count":
            self._handle_token_count(session, record)
            return []

        if event_type == "collab_agent_spawn_begin":
            self._update_last_ns(session, record)
            self._handle_collab_agent_spawn_begin(session, record, event)
            return []

        if event_type == "collab_agent_spawn_end":
            self._update_last_ns(session, record)
            self._handle_collab_agent_spawn_end(session, record, event)
            return []

        if event_type == "context_compacted":
            self._update_last_ns(session, record)
            self._handle_compaction(session, record, trigger="context_compacted")
            return []

        ns = self._update_last_ns(session, record)

        if event_type == "user_message":
            turn = self._active_turn(session, record)
            message = event.get("message", "")
            if message:
                session.user_prompts.append(message)
                turn.llm_input_messages.append({"role": "user", "content": message})
                if turn.root_span_ref:
                    turn.root_span_ref["meta"]["input"]["value"] = "\n\n".join(session.user_prompts)
                if turn.step_span_ref:
                    self._set_step_input(session, turn, turn.step_span_ref)
                self._adopt_orphan_proxy_llm_spans(session, turn)
            return []

        if event_type == "agent_message":
            turn = self._active_turn(session, record)
            message = event.get("message", "")
            if message:
                if turn.root_span_ref:
                    turn.root_span_ref["meta"]["output"]["value"] = message
                self._set_step_output(turn, message)
                self._set_llm_output(turn, message)
                self._emit_pending_llm_span(session, turn)
            return []

        if event_type == "task_complete":
            turn = self._active_turn(session, record)
            message = event.get("last_agent_message", "")
            if message:
                if turn.root_span_ref and not turn.root_span_ref["meta"]["output"]["value"]:
                    turn.root_span_ref["meta"]["output"]["value"] = message
                step = turn.step_span_ref or turn.last_step_span_ref
                if step is None or not step["meta"]["output"]["value"]:
                    self._set_step_output(turn, message)
                self._set_llm_output(turn, message)
                self._emit_pending_llm_span(session, turn)
            return self._finalize_turn(session, status="ok", end_ns=ns)

        if event_type == "turn_aborted":
            return self._finalize_turn(session, status="error", end_ns=ns)

        return []

    def _handle_response_item(self, session: CodexSession, record: Dict[str, Any]) -> None:
        payload = record.get("payload", {})
        item_type = payload.get("type", "")
        self._update_last_ns(session, record)

        if item_type == "function_call":
            self._handle_function_call(session, record)
        elif item_type == "function_call_output":
            self._handle_function_call_output(session, record)
        elif item_type == "reasoning":
            turn = self._active_turn(session, record)
            ns = _timestamp_to_ns(record.get("timestamp", ""))
            self._begin_llm_in_step(session, turn, ns)
        elif item_type == "message" and payload.get("role") == "assistant":
            turn = self._active_turn(session, record)
            ns = _timestamp_to_ns(record.get("timestamp", ""))
            message = _content_text(payload.get("content"))
            if turn.current_step_has_llm and _llm_has_text_output(turn.last_llm_span_ref, message):
                if turn.root_span_ref:
                    turn.root_span_ref["meta"]["output"]["value"] = message
                self._set_step_output(turn, message)
                return
            self._begin_llm_in_step(session, turn, ns)
            if message:
                _append_unique_message(turn.llm_output_messages, {"role": "assistant", "content": message})
                if turn.root_span_ref:
                    turn.root_span_ref["meta"]["output"]["value"] = message
                self._set_step_output(turn, message)
                if turn.last_llm_span_ref is not None and not turn.last_llm_span_ref["meta"]["output"].get("messages"):
                    turn.last_llm_span_ref["meta"]["output"]["messages"] = [{"role": "assistant", "content": message}]
                self._emit_pending_llm_span(session, turn)

    def _emit_pending_llm_span(self, session: CodexSession, turn: CodexTurn) -> None:
        usage = turn.pending_llm_usage
        if usage is None or turn.pending_llm_end_ns is None:
            return
        if turn.current_step_has_llm or not _has_llm_output(turn.llm_output_messages):
            return
        if turn.step_span_ref is None:
            self._ensure_step(session, turn, turn.pending_llm_end_ns)
        self._mark_llm_start(session, turn, turn.llm_start_ns or turn.current_step_start_ns or turn.pending_llm_end_ns)
        llm_start_ns = turn.llm_start_ns or turn.current_step_start_ns or turn.pending_llm_end_ns
        end_ns = turn.pending_llm_end_ns
        llm_input_messages = turn.active_llm_input_messages or self._llm_input_messages(session, turn)
        llm_output_messages = _copy_messages(turn.llm_output_messages)
        cached_input_tokens = usage.get("cached_input_tokens", 0)
        input_tokens = usage.get("input_tokens", 0)
        output_tokens = usage.get("output_tokens", 0)
        non_cached_input_tokens = max(input_tokens - cached_input_tokens, 0)
        metrics = {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": usage.get("total_tokens", 0),
            "cache_read_input_tokens": cached_input_tokens,
            "cached_input_tokens": cached_input_tokens,
            "cache_write_input_tokens": 0,
            "non_cached_input_tokens": non_cached_input_tokens,
            "reasoning_output_tokens": usage.get("reasoning_output_tokens", 0),
            **compute_openai_cost_metrics(
                model_id=session.model,
                non_cached_input_tokens=non_cached_input_tokens,
                cached_input_tokens=cached_input_tokens,
                output_tokens=output_tokens,
            ),
        }
        span: Dict[str, Any] = {
            "span_id": _format_span_id(),
            "trace_id": turn.trace_id,
            "parent_id": turn.step_span_id,
            "name": session.model or "unknown",
            "status": "ok",
            "start_ns": llm_start_ns,
            "duration": max(end_ns - llm_start_ns, 0),
            "ml_app": self._config.ml_app,
            "service": self._config.service,
            "env": self._config.env,
            "session_id": session.session_id,
            "tags": self._base_tags(session),
            "meta": {
                "span": {"kind": "llm"},
                "model_name": session.model,
                "model_provider": session.model_provider,
                "input": {"messages": _copy_messages(llm_input_messages)},
                "output": {"messages": _copy_messages(llm_output_messages)},
                "metadata": {"turn_id": turn.turn_id, "reasoning_effort": session.effort},
            },
            "metrics": metrics,
        }
        self._append_llm_span(turn, span)
        turn.llm_input_messages = _copy_messages(llm_input_messages)
        turn.llm_input_messages.extend(_copy_messages(llm_output_messages))
        turn.llm_input_messages.extend(_copy_messages(turn.pending_llm_input_messages))
        turn.pending_llm_input_messages = []
        turn.current_step_has_llm = True
        self._update_step_end(turn, turn.step_span_id, end_ns)
        turn.llm_start_ns = None
        turn.active_llm_input_messages = None
        turn.llm_output_messages = []
        turn.pending_llm_usage = None
        turn.pending_llm_end_ns = None

    def _handle_token_count(self, session: CodexSession, record: Dict[str, Any]) -> None:
        turn = self._active_turn(session, record)
        event = record.get("payload", {})
        info = event.get("info") or {}
        if not info:
            self._begin_llm_call(session, record)
            return
        usage = info.get("last_token_usage") or info.get("total_token_usage") or {}
        if not usage:
            return
        if turn.proxy_llm_spans_completed > turn.proxy_llm_usage_events_seen:
            turn.proxy_llm_usage_events_seen += 1
            return

        end_ns = self._update_last_ns(session, record)
        if turn.current_step_has_llm and not turn.llm_output_messages:
            return
        if turn.step_span_ref is None:
            self._ensure_step(session, turn, end_ns)
        self._mark_llm_start(session, turn, turn.llm_start_ns or turn.current_step_start_ns or end_ns)
        turn.pending_llm_usage = dict(usage)
        turn.pending_llm_end_ns = end_ns
        self._emit_pending_llm_span(session, turn)

    def _active_proxy_session(self, maybe_session_id: Optional[str] = None) -> Optional[CodexSession]:
        if maybe_session_id:
            session_id = self._proxy_session_ids.get(maybe_session_id, maybe_session_id)
            session = self._sessions.get(session_id)
            if session is not None:
                return session
            return None
        for session in reversed(list(self._sessions.values())):
            turn = session.active_turn
            if turn is not None and not turn.closed:
                return session
        if self._sessions:
            return next(reversed(self._sessions.values()))
        return None

    def begin_proxy_llm_call(self, maybe_session_id: Optional[str], start_ns: int) -> Optional[str]:
        """Reserve the active Codex step for a proxied LLM call."""
        session = self._active_proxy_session(maybe_session_id)
        if session is None or session.active_turn is None or session.active_turn.closed:
            return maybe_session_id
        turn = session.active_turn
        if turn.step_span_ref is not None and turn.current_step_has_llm and not session.pending_tools:
            self._close_current_step(turn)
        turn.proxy_llm_calls_started += 1
        turn.last_ns = max(turn.last_ns, start_ns)
        return session.session_id

    def register_proxy_llm_span(
        self,
        maybe_session_id: Optional[str],
        span: Dict[str, Any],
        start_ns: int,
        end_ns: int,
    ) -> None:
        """Attach a proxied LLM span to the active Codex turn, or buffer it."""
        session = self._active_proxy_session(maybe_session_id)
        if session is None or session.active_turn is None or session.active_turn.closed:
            session = self._matching_proxy_span_session(maybe_session_id, span)
        if session is None or session.active_turn is None or session.active_turn.closed:
            span["parent_id"] = "undefined"
            self._orphan_proxy_llm_spans.append((maybe_session_id, span))
            self._append_span(span)
            return

        self._attach_proxy_llm_span(session, session.active_turn, span, start_ns, end_ns)

    def _attach_proxy_llm_span(
        self,
        session: CodexSession,
        turn: CodexTurn,
        span: Dict[str, Any],
        start_ns: int,
        end_ns: int,
        append: bool = True,
    ) -> None:
        if turn.step_span_ref is None:
            self._ensure_step(session, turn, start_ns)
        if turn.proxy_llm_calls_started <= turn.proxy_llm_spans_completed:
            turn.proxy_llm_calls_started += 1

        span["trace_id"] = turn.trace_id
        span["parent_id"] = turn.step_span_id
        span["session_id"] = session.session_id
        span["ml_app"] = self._config.ml_app
        span["service"] = self._config.service
        span["env"] = self._config.env
        span["tags"] = self._base_tags(session, source="codex-proxy")
        if append:
            self._append_llm_span(turn, span)
        else:
            turn.last_llm_span_ref = span

        turn.proxy_llm_spans_completed += 1
        turn.current_step_has_llm = True
        turn.last_ns = max(turn.last_ns, end_ns)
        self._update_step_end(turn, turn.step_span_id, end_ns)
        turn.llm_start_ns = None
        turn.active_llm_input_messages = None
        turn.llm_output_messages = []

    def _adopt_orphan_proxy_llm_spans(self, session: CodexSession, turn: CodexTurn) -> None:
        if not self._orphan_proxy_llm_spans:
            return
        remaining: List[OrphanProxySpan] = []
        for maybe_session_id, span in self._orphan_proxy_llm_spans:
            if maybe_session_id:
                mapped_session_id = self._proxy_session_ids.get(maybe_session_id)
                if mapped_session_id:
                    if mapped_session_id != session.session_id:
                        remaining.append((maybe_session_id, span))
                        continue
                elif self._proxy_span_matches_session(span, session):
                    self._proxy_session_ids[maybe_session_id] = session.session_id
                else:
                    remaining.append((maybe_session_id, span))
                    continue
            elif span.get("session_id") and span.get("session_id") != session.session_id:
                remaining.append((maybe_session_id, span))
                continue
            start_ns = int(span.get("start_ns", turn.start_ns))
            end_ns = start_ns + int(span.get("duration", 0))
            self._attach_proxy_llm_span(session, turn, span, start_ns, end_ns, append=False)
        self._orphan_proxy_llm_spans = remaining

    def _tool_parent_id(self, session: CodexSession, turn: CodexTurn) -> str:
        """Return the parent span id for a new tool span.

        When a subagent (``collab_agent_spawn_begin``) is active, tool spans
        nest under the subagent span; otherwise they hang off the active step.
        """
        if session.agent_span_stack:
            return str(session.agent_span_stack[-1]["span_id"])
        return turn.step_span_id

    def _current_active_span_ref(self, session: CodexSession) -> Optional[Dict[str, Any]]:
        """Return the span dict most appropriate to annotate (e.g. compaction)."""
        if session.agent_span_stack:
            return session.agent_span_stack[-1].get("_span_ref")
        turn = session.active_turn
        if turn is None:
            return None
        return turn.step_span_ref or turn.last_step_span_ref or turn.root_span_ref

    def _handle_collab_agent_spawn_begin(
        self, session: CodexSession, record: Dict[str, Any], event: Dict[str, Any]
    ) -> None:
        turn = self._active_turn(session, record)
        start_ns = _timestamp_to_ns(record.get("timestamp", ""))
        self._ensure_step(session, turn, start_ns)
        call_id = str(event.get("call_id", "")) or _format_span_id()
        prompt = event.get("prompt", "")
        sender_thread_id = event.get("sender_thread_id", "")
        agent_name = event.get("new_agent_nickname") or event.get("agent_nickname") or "subagent"
        parent_id = self._tool_parent_id(session, turn)
        span_id = _format_span_id()
        span: Dict[str, Any] = {
            "span_id": span_id,
            "trace_id": turn.trace_id,
            "parent_id": parent_id,
            "name": str(agent_name),
            "status": "ok",
            "start_ns": start_ns,
            "duration": 0,
            "ml_app": self._config.ml_app,
            "service": self._config.service,
            "env": self._config.env,
            "session_id": session.session_id,
            "tags": self._base_tags(session) + ["subagent:true"],
            "meta": {
                "span": {"kind": "agent"},
                "input": {"value": prompt if isinstance(prompt, str) else _to_json_str(prompt)},
                "output": {"value": ""},
                "metadata": {
                    "subagent": {
                        "call_id": call_id,
                        "sender_thread_id": sender_thread_id,
                        "agent_nickname": str(agent_name),
                    }
                },
            },
            "metrics": {},
            "span_links": [],
        }
        self._append_span(span)
        entry: Dict[str, Any] = {
            "span_id": span_id,
            "parent_id": parent_id,
            "call_id": call_id,
            "start_ns": start_ns,
            "agent_name": str(agent_name),
            "_span_ref": span,
        }
        session.pending_subagents[call_id] = entry
        session.agent_span_stack.append(entry)

    def _handle_collab_agent_spawn_end(
        self, session: CodexSession, record: Dict[str, Any], event: Dict[str, Any]
    ) -> None:
        call_id = str(event.get("call_id", ""))
        entry = session.pending_subagents.pop(call_id, None)
        if entry is None:
            return
        end_ns = _timestamp_to_ns(record.get("timestamp", ""))
        # Unwind any subagents stacked above this one (out-of-order completion).
        try:
            idx = session.agent_span_stack.index(entry)
        except ValueError:
            idx = -1
        if idx >= 0:
            stale = session.agent_span_stack[idx + 1 :]
            del session.agent_span_stack[idx:]
            for stale_entry in stale:
                stale_span = stale_entry.get("_span_ref")
                if isinstance(stale_span, dict):
                    stale_span["duration"] = max(end_ns - int(stale_span.get("start_ns", end_ns)), 0)
                    stale_span["status"] = "error"
                    stale_span["meta"].setdefault("metadata", {}).setdefault("subagent", {})["status"] = "unwound"
                session.pending_subagents.pop(str(stale_entry.get("call_id", "")), None)
        span = entry.get("_span_ref")
        if isinstance(span, dict):
            span["duration"] = max(end_ns - int(span.get("start_ns", end_ns)), 0)
            status = str(event.get("status", "")) or "ok"
            span["status"] = "ok" if status in ("ok", "success", "") else "error"
            metadata = span["meta"].setdefault("metadata", {}).setdefault("subagent", {})
            metadata["status"] = status
            new_thread_id = event.get("new_thread_id")
            if new_thread_id:
                metadata["child_session_id"] = str(new_thread_id)
            new_agent_role = event.get("new_agent_role")
            if new_agent_role:
                metadata["agent_role"] = str(new_agent_role)
            new_agent_nickname = event.get("new_agent_nickname")
            if new_agent_nickname:
                metadata["agent_nickname"] = str(new_agent_nickname)
                # Only nickname becomes available at spawn_end — backfill the
                # preliminary span's display name if we haven't already.
                if span.get("name") in ("", "subagent", entry.get("agent_name")):
                    span["name"] = str(new_agent_nickname)

    def _handle_compaction(self, session: CodexSession, record: Dict[str, Any], trigger: str) -> None:
        span_ref = self._current_active_span_ref(session)
        if span_ref is None:
            return
        meta = span_ref.setdefault("meta", {})
        metadata = meta.setdefault("metadata", {})
        dd = metadata.setdefault("_dd", {})
        compactions = dd.setdefault("compactions", [])
        compactions.append(
            {
                "trigger": trigger,
                "timestamp_ns": _timestamp_to_ns(record.get("timestamp", "")),
            }
        )

    def _deduplicate_tool_use_id(self, session: CodexSession, call_id: str) -> str:
        """Return a session-unique tool_use_id.

        Codex sometimes reuses ``call_id`` across turns (e.g. ``web_search_2``).
        Suffix repeats with an occurrence counter so trace consumers can pair
        each ``function_call`` with its matching ``function_call_output``
        without collisions. Direct port of trajectory's ``deduplicateToolUseID``
        (``trajectory/codex/mapper/mapper.go``).
        """
        count = session.seen_tool_use_ids.get(call_id, 0) + 1
        session.seen_tool_use_ids[call_id] = count
        if count == 1:
            return call_id
        return f"{call_id}_{count}"

    def _handle_function_call(self, session: CodexSession, record: Dict[str, Any]) -> None:
        turn = self._active_turn(session, record)
        payload = record.get("payload", {})
        call_id = payload.get("call_id", "") or _format_span_id()
        unique_id = self._deduplicate_tool_use_id(session, call_id)
        session.tool_use_id_map[call_id] = unique_id
        tool_name = payload.get("name", "unknown_tool") or "unknown_tool"
        session.tools_used.add(tool_name)
        self._update_agent_manifest(session)
        start_ns = _timestamp_to_ns(record.get("timestamp", ""))
        self._ensure_step(session, turn, start_ns)
        appending_to_existing_llm = (
            turn.current_step_has_llm
            and turn.last_llm_span_ref is not None
            and turn.last_llm_span_ref.get("parent_id") == turn.step_span_id
        )
        if not appending_to_existing_llm:
            self._mark_llm_start(session, turn, start_ns)
        self._update_step_end(turn, turn.step_span_id, start_ns)

        arguments = payload.get("arguments", "")
        tool_input: Any = arguments
        if isinstance(arguments, str):
            try:
                tool_input = json.loads(arguments)
            except (ValueError, TypeError):
                tool_input = arguments
        tool_call_message = {
            "role": "assistant",
            "content": _to_json_str(tool_input),
            "tool_calls": [{"id": unique_id, "name": tool_name, "arguments": tool_input}],
        }
        llm_span = turn.last_llm_span_ref
        if appending_to_existing_llm and llm_span is not None:
            output_messages = llm_span["meta"]["output"].setdefault("messages", [])
            _append_or_update_tool_call_message(output_messages, tool_call_message)
        else:
            _append_or_update_tool_call_message(turn.llm_output_messages, tool_call_message)
        if turn.step_span_ref is not None and not turn.step_span_ref["meta"]["output"]["value"]:
            turn.step_span_ref["meta"]["output"]["value"] = _to_json_str(tool_input)
        self._emit_pending_llm_span(session, turn)

        session.pending_tools[unique_id] = PendingToolSpan(
            span_id=_format_span_id(),
            tool_name=tool_name,
            tool_input=tool_input,
            parent_id=self._tool_parent_id(session, turn),
            start_ns=start_ns,
        )

    def _emit_tool_span(
        self,
        session: CodexSession,
        pending: PendingToolSpan,
        end_ns: int,
        output_value: str,
        is_error: bool,
    ) -> None:
        span = {
            "span_id": pending.span_id,
            "trace_id": session.active_turn.trace_id if session.active_turn else _format_trace_id(),
            "parent_id": pending.parent_id,
            "name": pending.tool_name,
            "status": "error" if is_error else "ok",
            "start_ns": pending.start_ns,
            "duration": max(end_ns - pending.start_ns, 0),
            "ml_app": self._config.ml_app,
            "service": self._config.service,
            "env": self._config.env,
            "session_id": session.session_id,
            "tags": self._base_tags(session) + [f"tool_name:{pending.tool_name}"],
            "meta": {
                "span": {"kind": "tool"},
                "input": {"value": _to_json_str(pending.tool_input)},
                "output": {"value": output_value},
                "metadata": {},
            },
            "metrics": {},
            "span_links": [],
        }
        self._append_span(span)
        turn = session.active_turn
        if turn is not None:
            self._update_step_end(turn, pending.parent_id, end_ns)

    def _handle_function_call_output(self, session: CodexSession, record: Dict[str, Any]) -> None:
        payload = record.get("payload", {})
        call_id = payload.get("call_id", "")
        unique_id = session.tool_use_id_map.pop(call_id, call_id)
        pending = session.pending_tools.pop(unique_id, None)
        if pending is None:
            return
        output = payload.get("output", "")
        output_value = output if isinstance(output, str) else _to_json_str(output)
        tool_message = {"role": "tool", "tool_call_id": unique_id, "content": output_value}
        if session.active_turn is not None and session.active_turn.active_llm_input_messages is not None:
            session.active_turn.pending_llm_input_messages.append(tool_message)
        elif session.active_turn is not None:
            session.active_turn.llm_input_messages.append(tool_message)
        self._emit_tool_span(
            session=session,
            pending=pending,
            end_ns=_timestamp_to_ns(record.get("timestamp", "")),
            output_value=output_value,
            is_error=False,
        )

    def _dispatch(
        self, session_id: str, record: Dict[str, Any], proxy_session_key: Optional[str] = None
    ) -> List[CompletedTrace]:
        start_ns = _timestamp_to_ns(record.get("timestamp", ""))
        session = self._get_or_create_session(session_id, start_ns=start_ns)
        try:
            record_fingerprint = json.dumps(record, sort_keys=True, separators=(",", ":"))
        except (TypeError, ValueError):
            record_fingerprint = ""
        if record_fingerprint:
            if record_fingerprint in session.seen_records:
                return []
            session.seen_records.add(record_fingerprint)

        record_type = record.get("type", "")

        if record_type == "session_meta":
            self._handle_session_meta(session, record)
        elif record_type == "turn_context":
            return self._start_turn(session, record)
        elif record_type == "event_msg":
            return self._handle_event_msg(session, record)
        elif record_type == "response_item":
            self._handle_response_item(session, record)
        elif record_type == "compacted":
            self._update_last_ns(session, record)
            self._handle_compaction(session, record, trigger="compacted")
        else:
            self._update_last_ns(session, record)
        return []

    def _unwrap_body(self, body: Dict[str, Any]) -> Tuple[str, Dict[str, Any], Optional[str]]:
        record = body.get("record", body)
        session_id = body.get("session_id", "")
        proxy_session_key = body.get("proxy_session_key") or None
        if isinstance(record, dict):
            payload = record.get("payload", {})
            if not isinstance(payload, dict):
                payload = {}
            if not session_id:
                session_id = record.get("session_id", "") or payload.get("session_id", "")
            if not session_id and record.get("type") == "session_meta":
                session_id = payload.get("id", "")
            if not session_id:
                session_id = self._last_session_id
            if not session_id and len(self._sessions) == 1:
                session_id = next(iter(self._sessions))
        return session_id, record, proxy_session_key

    async def handle_hook(self, request: Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)

        session_id, record, proxy_session_key = self._unwrap_body(body)
        if not session_id:
            return web.json_response({"error": "missing session_id"}, status=400)

        self._raw_events.append(body)
        self._last_session_id = session_id
        completed = self._dispatch(session_id, record, proxy_session_key=proxy_session_key)
        for completed_session_id, completed_trace_id in completed:
            await self._hooks_api._forward_trace_to_backend(
                completed_session_id, trace_id=completed_trace_id, span_source="Codex"
            )
            await self._hooks_api._forward_eval_metrics_to_backend(completed_session_id, trace_id=completed_trace_id)
        return web.json_response({"status": "ok"})

    async def handle_raw_events(self, request: Request) -> web.Response:
        return web.json_response({"events": self._raw_events})

    def get_routes(self) -> List[web.RouteDef]:
        return [
            web.post("/codex/hooks", with_cors(self.handle_hook)),
            web.route("*", "/codex/hooks/raw", with_cors(self.handle_raw_events)),
        ]
