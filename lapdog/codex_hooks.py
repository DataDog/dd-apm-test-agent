"""Codex session JSONL -> LLM Observability spans."""

from collections import OrderedDict
from collections import deque
import datetime
from decimal import Decimal
import hashlib
import json
import logging
import math
import os
import re
import shlex
import socket
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TypeVar

from aiohttp import web
from aiohttp.web import Request

from ddapm_test_agent.cors import with_cors

from .claude_hooks import ClaudeHooksAPI
from .claude_hooks import SessionState
from .claude_hooks import _format_span_id
from .claude_hooks import _format_trace_id
from .claude_hooks import _to_json_str
from .coding_agent_metadata import apply_project_metadata_to_span
from .coding_agent_metadata import extract_agent_project_name
from .coding_agent_metadata import extract_git_repository_url
from .coding_agent_metadata import resolve_project_metadata
from .model_pricing import compute_cost_metrics
from .utils import set_hidden_metadata

log = logging.getLogger(__name__)


def _item_interval(event: Dict[str, Any], earliest_ns: int, latest_ns: int) -> Optional[Tuple[int, int]]:
    start, end = event.get("started_at_ms"), event.get("completed_at_ms")
    if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool):
        return None
    start_ns, end_ns = start * 1_000_000, end * 1_000_000
    # Sub-millisecond commands can have equal millisecond timestamps. Keep
    # their finer duration fallback in that case.
    if earliest_ns <= start_ns < end_ns <= latest_ns:
        return start_ns, end_ns
    return None


def _optional_limit(name: str) -> Optional[int]:
    value = os.environ.get(name)
    return int(value) if value is not None else None


MAX_LLM_MESSAGE_CHARS = _optional_limit("DD_CODEX_MAX_LLM_MESSAGE_CHARS")
MAX_TOOL_VALUE_CHARS = _optional_limit("DD_CODEX_MAX_TOOL_VALUE_CHARS")

_OK_TOOL_STATUSES = {"", "ok", "success", "succeeded", "completed", "complete"}
_IN_FLIGHT_TOOL_STATUSES = {"pending", "queued", "running", "in_progress", "started"}
_ERROR_TOOL_STATUSES = {
    "cancelled",
    "canceled",
    "denied",
    "error",
    "errored",
    "failed",
    "failure",
    "rejected",
    "timed_out",
    "timeout",
}
_EXEC_WRAPPER_NAMES = {"exec", "functions.exec"}


def _timestamp_to_ns(timestamp: str) -> int:
    if not timestamp:
        return int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1_000_000_000)
    try:
        dt = datetime.datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return int(dt.replace(microsecond=0).timestamp()) * 1_000_000_000 + dt.microsecond * 1_000
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


def _is_user_authored_message(payload: Dict[str, Any]) -> bool:
    """Return whether a Codex ``role=user`` item contains human-authored input."""
    metadata = payload.get("internal_chat_message_metadata_passthrough", {})
    if not isinstance(metadata, dict):
        return True
    content_item_kinds = metadata.get("content_item_kinds")
    if not isinstance(content_item_kinds, list):
        return True
    return any(str(kind).startswith("user.") for kind in content_item_kinds)


def _event_type(kind: str, payload: Dict[str, Any]) -> str:
    """Map JSONL record formats to span operations before changing state."""
    event = str(payload.get("type") or "")
    if kind == "turn_context":
        return "start" if payload.get("turn_id") else ""
    if kind == "token_usage_record":
        return "usage"
    if kind == "compacted" or event == "context_compacted":
        return "compaction"
    if kind == "response_item":
        if event == "message":
            if payload.get("role") == "user" and _is_user_authored_message(payload):
                return "prompt"
            return "model" if payload.get("role") == "assistant" else ""
        if event in ("reasoning", "function_call", "custom_tool_call"):
            return "model"
        if event in ("function_call_output", "custom_tool_call_output"):
            return "tool_output"
    if kind == "event_msg" and event in ("task_started", "user_message"):
        return "start" if event == "task_started" else "prompt"
    return {
        "item_started": "item",
        "item_completed": "item",
        "web_search_call": "tool_result",
        "patch_apply_end": "tool_result",
        "task_complete": "finish",
        "turn_aborted": "finish",
        "shutdown_complete": "finish",
        "collab_agent_spawn_begin": "subagent",
        "collab_agent_spawn_end": "subagent",
        "exec_approval_request": "approval",
        "apply_patch_approval_request": "approval",
        "token_count": "token_count",
        "agent_message": "agent_message",
        "session_name": "session_name",
    }.get(event, "")


def _copy_messages(messages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    copied, _ = _copy_messages_with_limits(messages)
    return copied


def _truncate_text(value: str, max_chars: Optional[int]) -> Tuple[str, bool]:
    if max_chars is None:
        return value, False
    if max_chars <= 0:
        return "", bool(value)
    if len(value) <= max_chars:
        return value, False
    omitted = len(value) - max_chars
    return f"{value[:max_chars]}\n\n[truncated {omitted} chars]", True


def _truncate_display_value(value: Any, max_chars: Optional[int]) -> Tuple[Any, bool]:
    if isinstance(value, str):
        return _truncate_text(value, max_chars)
    if value is None:
        return value, False
    rendered = _to_json_str(value)
    truncated, was_truncated = _truncate_text(rendered, max_chars)
    return (truncated, True) if was_truncated else (value, False)


def _copy_reasoning_items(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [dict(item) for item in items]


def _copy_messages_with_limits(messages: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], bool]:
    copied_messages: List[Dict[str, Any]] = []
    was_truncated = False
    for message in messages:
        copied = dict(message)
        if "content" in copied:
            copied["content"], truncated = _truncate_display_value(copied.get("content"), MAX_LLM_MESSAGE_CHARS)
            was_truncated = was_truncated or truncated
        tool_calls = copied.get("tool_calls")
        if isinstance(tool_calls, list):
            copied_tool_calls = []
            for tool_call in tool_calls:
                if not isinstance(tool_call, dict):
                    copied_tool_calls.append(tool_call)
                    continue
                copied_tool_call = dict(tool_call)
                if "arguments" in copied_tool_call:
                    copied_tool_call["arguments"], truncated = _truncate_display_value(
                        copied_tool_call.get("arguments"), MAX_LLM_MESSAGE_CHARS
                    )
                    was_truncated = was_truncated or truncated
                reasoning = copied_tool_call.get("reasoning")
                if isinstance(reasoning, list):
                    copied_tool_call["reasoning"] = _copy_reasoning_items(
                        [item for item in reasoning if isinstance(item, dict)]
                    )
                copied_tool_calls.append(copied_tool_call)
            copied["tool_calls"] = copied_tool_calls
        copied_messages.append(copied)
    return copied_messages, was_truncated


def _normalize_status(status: Any) -> str:
    return str(status or "").strip().lower()


def _tool_status_is_error(status: Any) -> bool:
    normalized = _normalize_status(status)
    if normalized in _ERROR_TOOL_STATUSES:
        return True
    if normalized in _OK_TOOL_STATUSES or normalized in _IN_FLIGHT_TOOL_STATUSES:
        return False
    return normalized.startswith("failed") or normalized.startswith("error")


def _canonical_tool_status(status: Any, is_error: bool = False) -> str:
    normalized = _normalize_status(status)
    if is_error and (not normalized or normalized in _IN_FLIGHT_TOOL_STATUSES):
        return "failed"
    if normalized in _ERROR_TOOL_STATUSES or normalized.startswith("failed") or normalized.startswith("error"):
        return "failed"
    if normalized in _OK_TOOL_STATUSES:
        return "completed" if normalized else ""
    return normalized


def _reasoning_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        parts = []
        for key in ("text", "summary_text", "content", "output_text"):
            text = value.get(key)
            if isinstance(text, str) and text:
                parts.append(text)
        return "\n".join(parts)
    if isinstance(value, list):
        parts = [_reasoning_text(item) for item in value]
        return "\n".join(part for part in parts if part)
    return ""


def _extract_reasoning_metadata(payload: Dict[str, Any]) -> Dict[str, Any]:
    reasoning: Dict[str, Any] = {}
    reasoning_id = payload.get("id")
    if reasoning_id:
        reasoning["id"] = str(reasoning_id)
    status = _normalize_status(payload.get("status", ""))
    if status:
        reasoning["status"] = status
    text = (
        _reasoning_text(payload.get("summary"))
        or _reasoning_text(payload.get("content"))
        or _reasoning_text(payload.get("text"))
    )
    if text:
        text, truncated = _truncate_text(text, MAX_LLM_MESSAGE_CHARS)
        reasoning["text"] = text
        if truncated:
            reasoning["truncated"] = True
    if payload.get("encrypted_content"):
        reasoning["encrypted"] = True
    return reasoning


# The parser owns task structure. The proxy supplies measurements only.
# Completed span dictionaries belong to the shared UI store; these indexes
# retain references, not a second copy of transcript bodies.
RECENT_TURNS = 128
RECENT_RESPONSES = 2048
RECENT_RECORDS = 8192
LATE_EVENT_SECONDS = 300
RAW_EVENT_LIMIT = 256
Span = Dict[str, Any]
CompletedTrace = Tuple[str, str]
_K = TypeVar("_K")
_V = TypeVar("_V")


def _remember(index: OrderedDict[_K, _V], key: _K, value: _V, limit: int) -> None:
    index[key] = value
    index.move_to_end(key)
    while len(index) > limit:
        index.popitem(last=False)


TOOL_DISPLAY_NAMES = {"write_stdin": "Ran", "apply_patch": "Apply patch", "web__run": "Web", "view_image": "View image"}
SHELL_COMMAND_DISPLAY_NAMES = {"cat": "Read", "sed": "Read", "find": "List", "ls": "List", "rg": "List", "curl": "Web"}


def _shell_command_name(arguments: Any) -> str:
    if not isinstance(arguments, dict) or not isinstance(arguments.get("cmd"), str):
        return "Ran"
    try:
        lexer = shlex.shlex(arguments["cmd"], posix=True, punctuation_chars=";&|")
        lexer.whitespace_split = True
        lexer.commenters = ""
        tokens = list(lexer)
    except ValueError:
        return "Ran"
    index = 0
    while index < len(tokens):
        token = tokens[index]
        if token == "cd":
            while index < len(tokens) and tokens[index] not in ("&&", ";"):
                index += 1
            index += 1
            continue
        if token in ("env", "command") or re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*=.*", token):
            index += 1
            continue
        command = os.path.basename(token)
        return SHELL_COMMAND_DISPLAY_NAMES.get(command, "Ran")
    return "Ran"


def _display_tool_name(name: str, arguments: Any = None) -> str:
    if name == "exec_command":
        return _shell_command_name(arguments)
    if name in TOOL_DISPLAY_NAMES:
        return TOOL_DISPLAY_NAMES[name]
    return name.rsplit("__", 1)[-1].replace("_", " ").strip().capitalize() or name


def _tool_item(item: Dict[str, Any]) -> Optional[Tuple[str, Any, Any, Dict[str, Any]]]:
    """Normalize recorded tool results. Never interpret JavaScript or printed output."""
    kind = item.get("type")
    if kind == "CommandExecution":
        command = item.get("command") or []
        if not isinstance(command, list) or not command:
            return None
        return (
            "exec_command",
            {
                "cmd": (
                    command[-1] if len(command) >= 3 and command[-2] in ("-c", "-lc") else shlex.join(map(str, command))
                )
            },
            item.get("aggregated_output", ""),
            {key: item[key] for key in ("process_id", "exit_code", "cwd") if key in item},
        )
    if kind == "FileChange":
        return "apply_patch", item.get("changes", {}), str(item.get("stdout") or "") + str(item.get("stderr") or ""), {}
    if kind == "McpToolCall":
        server, name = item.get("server", ""), item.get("tool", "")
        if server != "codex" and name not in ("read_mcp_resource", "list_mcp_resources", "list_mcp_resource_templates"):
            name = f"mcp__{server}__{name}"
        name = re.sub(r"[^a-zA-Z0-9_]", "_", name)
        return name, item.get("arguments", {}), item.get("result", item.get("error", "")), {"server": server}
    if kind == "Extension":
        name = "web__run" if str(item.get("kind", "")).startswith("web.") else str(item.get("kind") or "extension")
        return name, item.get("action", {}), item.get("results", item.get("result", "")), {}
    return None


def _matches_tool_input(name: str, recorded: str, arguments: Any, cwd: str) -> bool:
    """Compare the fields available in both a direct call and its structured item."""
    if recorded == _to_json_str(arguments):
        return True
    try:
        original = json.loads(recorded)
    except ValueError:
        original = recorded
    if name == "exec_command":
        return isinstance(original, dict) and original.get("cmd") == arguments.get("cmd")
    if name == "apply_patch" and isinstance(original, str) and isinstance(arguments, dict):
        paths = [
            line.split(": ", 1)[1]
            for line in original.splitlines()
            if line.startswith(("*** Update File: ", "*** Add File: ", "*** Delete File: "))
        ]
        # Resolve relative paths against the recorded workspace, not Lapdog's cwd.
        return (
            bool(paths)
            and len(paths) == len(arguments)
            and {os.path.normpath(os.path.join(cwd, path)) for path in paths}
            == {os.path.normpath(os.path.join(cwd, path)) for path in arguments}
        )
    return bool(original == arguments)


class CodexConfig:
    def __init__(self) -> None:
        self.ml_app = os.environ.get("DD_CODEX_ML_APP", "codex")
        self.service = self.ml_app
        self.env = "local"
        self.agent_name = self.ml_app
        self.hostname = socket.gethostname()
        self.user_handle = os.environ.get("DD_USER_HANDLE", "")


class Response:
    def __init__(self, step: Span, start: int) -> None:
        self.step = step
        self.start = start
        self.timing = "record_timestamp"
        self.output: List[Dict[str, Any]] = []
        self.reasoning: List[Dict[str, Any]] = []
        self.llm: Optional[Span] = None
        self.response_id = ""
        self.usage: Optional[Tuple[Dict[str, Any], int, bool]] = None
        self.inputs: List[Dict[str, Any]] = []


class Turn:
    def __init__(self, turn_id: str, root: Span) -> None:
        self.turn_id = turn_id
        self.root = root
        self.responses: List[Response] = []
        self.current: Optional[Response] = None
        self.calls: Dict[str, Tuple[Response, Optional[Span]]] = {}
        self.tools: Dict[str, Span] = {}
        self.item_starts: Dict[str, int] = {}
        self.messages: List[Dict[str, Any]] = []
        self.subagents: Dict[str, Span] = {}
        self.closed = False
        self.closed_at = 0.0
        self.last_ns = root["start_ns"]
        self.last_prompt: Optional[Tuple[str, str]] = None
        self.modern_usage = False
        self.provisional = False
        self.call_counts: Dict[str, int] = {}


class CodexSession:
    def __init__(self, session_id: str) -> None:
        self.raw_session_id = session_id
        self.session_id = session_id
        self.cwd = ""
        self.model = ""
        self.effort = ""
        self.cli_version = ""
        self.model_provider = "openai"
        self.project_metadata = resolve_project_metadata()
        self.active_turn: Optional[Turn] = None
        self.last_seen = time.monotonic()
        self.replayed_turn = False


class CodexHooksAPI:
    """Normalize JSONL records and update each identified operation in one place."""

    def __init__(self, hooks_api: ClaudeHooksAPI) -> None:
        self._hooks_api = hooks_api
        self._config = CodexConfig()
        self._sessions: Dict[str, CodexSession] = {}
        self._turns: OrderedDict[Tuple[str, str], Tuple[CodexSession, Turn]] = OrderedDict()
        self._responses: OrderedDict[Tuple[str, str], Tuple[CodexSession, Turn, Response]] = OrderedDict()
        self._pending_proxy: OrderedDict[str, Tuple[float, Span]] = OrderedDict()
        self._seen: OrderedDict[bytes, bool] = OrderedDict()
        self._raw_events: deque[Dict[str, Any]] = deque(maxlen=RAW_EVENT_LIMIT)
        self._child_session_ids: OrderedDict[str, str] = OrderedDict()
        self._reviews: OrderedDict[str, Dict[str, Any]] = OrderedDict()
        self._pending_reviews: OrderedDict[Tuple[str, str, str, str], Tuple[float, Dict[str, Any]]] = OrderedDict()

    def _session(self, sid: str) -> CodexSession:
        if sid not in self._sessions:
            session = CodexSession(sid)
            session.session_id = self._child_session_ids.get(sid, sid)
            self._sessions[sid] = session
            if sid not in self._hooks_api._sessions:
                self._hooks_api._sessions[sid] = SessionState(
                    session_id=session.session_id,
                    trace_id=_format_trace_id(),
                    root_span_id=_format_span_id(),
                    start_ns=0,
                )
        return self._sessions[sid]

    def _expire(self) -> None:
        now = time.monotonic()
        for key, (session, turn) in list(self._turns.items()):
            if turn.closed and (now - turn.closed_at > LATE_EVENT_SECONDS or len(self._turns) > RECENT_TURNS):
                del self._turns[key]
                if session.active_turn is turn:
                    session.active_turn = None
        for key, (session, turn, response) in list(self._responses.items()):
            if (session.raw_session_id, turn.turn_id) not in self._turns:
                del self._responses[key]
        for response_id, (created, span) in list(self._pending_proxy.items()):
            if now - created > LATE_EVENT_SECONDS:
                del self._pending_proxy[response_id]
        for review_key, (created, review) in list(self._pending_reviews.items()):
            if now - created > LATE_EVENT_SECONDS:
                del self._pending_reviews[review_key]
        for sid, session in list(self._sessions.items()):
            if (
                session.active_turn is None
                and now - session.last_seen > LATE_EVENT_SECONDS
                and not any(owner is session for owner, _ in self._turns.values())
            ):
                del self._sessions[sid]

    def _span(
        self,
        session: CodexSession,
        kind: str,
        name: str,
        start: int,
        parent: Optional[str] = None,
        trace: Optional[str] = None,
    ) -> Span:
        span = {
            "span_id": _format_span_id(),
            "trace_id": trace or _format_trace_id(),
            "parent_id": parent or "undefined",
            "name": name,
            "start_ns": start,
            "duration": 0,
            "status": "ok",
            "session_id": session.session_id,
            "ml_app": self._config.ml_app,
            "service": self._config.service,
            "env": self._config.env,
            "tags": self._hooks_api.base_tags(
                session, source="codex-jsonl", ml_app=self._config.ml_app, user_handle=self._config.user_handle
            ),
            "meta": {"span": {"kind": kind}, "input": {}, "output": {}, "metadata": {}},
            "metrics": {},
        }
        apply_project_metadata_to_span(span, session.project_metadata)
        index = None
        if kind == "llm":
            index = next(
                (i for i, child in enumerate(self._hooks_api._assembled_spans) if child.get("parent_id") == parent),
                None,
            )
        self._hooks_api._append_span(span, index=index)
        return span

    @staticmethod
    def _bounds(span: Span, start: int, end: int) -> None:
        previous_end = span["start_ns"] + span["duration"]
        span["start_ns"] = min(span["start_ns"], start)
        span["duration"] = max(previous_end, end) - span["start_ns"]

    def _start(
        self, session: CodexSession, turn_id: str, ns: int, provisional: bool = False
    ) -> Tuple[Turn, List[CompletedTrace]]:
        key = (session.raw_session_id, turn_id)
        if key in self._turns:
            return self._turns[key][1], []
        previous = session.active_turn
        if not provisional and previous is not None and previous.provisional and not previous.closed:
            self._turns.pop((session.raw_session_id, previous.turn_id), None)
            previous.turn_id = turn_id
            previous.provisional = False
            previous.root["meta"]["metadata"]["turn_id"] = turn_id
            self._turns[key] = (session, previous)
            return previous, []
        completed = self._finish(session, session.active_turn, ns)
        root = self._span(session, "agent", "codex-request", ns)
        root["meta"].update(model_name=session.model, model_provider=session.model_provider)
        root["meta"]["metadata"].update(
            turn_id=turn_id,
            cwd=session.cwd,
            codex_cli_version=session.cli_version,
            reasoning_effort=session.effort,
        )
        root["meta"]["input"]["value"] = ""
        root["meta"]["output"]["value"] = ""
        root["tags"].append("trajectory.semantic_type:turn")
        turn = Turn(turn_id, root)
        turn.provisional = provisional
        self._manifest(session, turn)
        session.active_turn = turn
        self._turns[key] = (session, turn)
        shared = self._hooks_api._sessions[session.raw_session_id]
        shared.trace_id, shared.root_span_id, shared.start_ns = root["trace_id"], root["span_id"], ns
        return turn, completed

    def _finish(self, session: CodexSession, turn: Optional[Turn], ns: int, status: str = "ok") -> List[CompletedTrace]:
        if turn is None or turn.closed:
            return []
        ns = max(ns, turn.last_ns)
        for span in turn.tools.values():
            if span["meta"]["metadata"].get("status") in ("running", "pending", "in_progress"):
                response = next(r for r in turn.responses if r.step["span_id"] == span["meta"]["metadata"]["step_id"])
                self._end_tool(turn, response, span, ns, "", True)
        for span in turn.subagents.values():
            if span["duration"] == 0:
                span["duration"] = max(ns - span["start_ns"], 0)
                span["status"] = "error"
                span["meta"]["metadata"]["subagent"]["status"] = "unterminated"
        turn.root["duration"] = max(ns - turn.root["start_ns"], 0)
        turn.root["status"] = status
        tools = sorted({span["name"] for span in turn.tools.values()})
        turn.root["meta"]["metadata"]["tools"] = tools
        self._manifest(session, turn)
        turn.closed = True
        turn.closed_at = time.monotonic()
        self._attach_reviews(session, turn)
        # Only IDs and references to canonical spans survive for late updates.
        turn.calls.clear()
        turn.messages.clear()
        turn.item_starts.clear()
        for response in turn.responses:
            response.output.clear()
            response.reasoning.clear()
            response.inputs.clear()
            response.usage = None
        return [(session.session_id, turn.root["trace_id"])]

    def _response(self, session: CodexSession, turn: Turn, ns: int) -> Response:
        if turn.current is None or turn.current.llm is not None:
            step = self._span(
                session, "step", f"inference-{len(turn.responses)}", ns, turn.root["span_id"], turn.root["trace_id"]
            )
            step["tags"].append("trajectory.semantic_type:agent_message")
            step["meta"]["metadata"].update(turn_id=turn.turn_id, message_index=len(turn.responses))
            turn.current = Response(step, ns)
            turn.current.inputs = list(turn.messages)
            step["meta"]["input"]["value"] = (
                _to_json_str([m for m in turn.messages if m["role"] != "assistant"])
                if turn.responses
                else turn.root["meta"]["input"]["value"]
            )
            turn.responses.append(turn.current)
        return turn.current

    def _model_start(self, turn: Turn, payload: Dict[str, Any], ns: int) -> Tuple[int, str]:
        metadata = payload.get("internal_chat_message_metadata_passthrough") or {}
        created = metadata.get("create_time") if isinstance(metadata, dict) else None
        if (
            isinstance(created, (float, int))
            and not isinstance(created, bool)
            and math.isfinite(created)
            and turn.root["start_ns"] / 1e9 <= created <= ns / 1e9
        ):
            return int(Decimal(str(created)) * 1_000_000_000), "response_create_time"
        return turn.item_starts.get(str(payload.get("id") or ""), ns), (
            "item_completed" if payload.get("id") in turn.item_starts else "record_timestamp"
        )

    def _model_item(self, session: CodexSession, turn: Turn, payload: Dict[str, Any], ns: int) -> None:
        start, source = self._model_start(turn, payload, ns)
        response = self._response(session, turn, start)
        if start <= response.start:
            response.start, response.timing = start, source
        self._bounds(response.step, start, ns)
        kind = payload.get("type")
        if kind == "reasoning":
            response.reasoning.append(_extract_reasoning_metadata(payload))
            return
        if kind == "message":
            text = _content_text(payload.get("content"))
            if text:
                message = {"role": "assistant", "content": text}
                if message not in response.output:
                    response.output.append(message)
                turn.root["meta"]["output"]["value"] = text
                response.step["meta"]["output"]["value"] = text
                if response.usage:
                    pending, end, modern = response.usage
                    self._usage(session, turn, pending, end, modern)
            return
        call_id = str(payload.get("call_id") or payload.get("id") or _format_span_id())
        # Repeated arguments do not imply repeated identity.
        existing = turn.calls.get(call_id)
        if existing and existing[1] is not None and existing[1]["meta"]["metadata"]["status"] == "running":
            return
        name = str(payload.get("name") or "unknown_tool")
        arguments = payload.get("input") if kind == "custom_tool_call" else payload.get("arguments", {})
        if kind == "function_call" and isinstance(arguments, str):
            try:
                arguments = json.loads(arguments)
            except ValueError:
                pass
        response.step["meta"]["output"]["value"] = _to_json_str(arguments)
        response.output.append(
            {
                "role": "assistant",
                "content": _to_json_str(arguments),
                "tool_calls": [
                    {
                        "id": call_id,
                        "name": _display_tool_name(name, arguments) if name not in _EXEC_WRAPPER_NAMES else name,
                        "arguments": arguments,
                        "status": payload.get("status", "completed"),
                        **({"reasoning": _copy_reasoning_items(response.reasoning)} if response.reasoning else {}),
                    }
                ],
            }
        )
        span = None
        if name not in _EXEC_WRAPPER_NAMES:
            count = turn.call_counts.get(call_id, 0) + 1
            turn.call_counts[call_id] = count
            unique_id = call_id if count == 1 else f"{call_id}_{count}"
            span = self._tool(session, turn, response, unique_id, name, arguments, ns)
            if response.reasoning:
                span["meta"]["metadata"]["reasoning"] = _copy_reasoning_items(response.reasoning)
        turn.calls[call_id] = (response, span)
        if response.usage:
            pending, end, modern = response.usage
            self._usage(session, turn, pending, end, modern)

    def _usage(self, session: CodexSession, turn: Turn, payload: Dict[str, Any], ns: int, modern: bool) -> None:
        response_id = str(payload.get("response_id") or "")
        if modern:
            turn.modern_usage = True
            key = (session.raw_session_id, response_id)
            if not response_id or key in self._responses:
                return
            usage = payload.get("usage") or {}
        else:
            if turn.modern_usage:
                return
            info = payload.get("info") or {}
            usage = info.get("last_token_usage") or info.get("total_token_usage") or {}
        if not usage:
            return
        response = turn.current or self._response(session, turn, ns)
        if response.llm is not None:
            return
        if not response.output:
            response.usage = (payload, ns, modern)
            return
        span = self._span(
            session, "llm", session.model or "unknown", response.start, response.step["span_id"], turn.root["trace_id"]
        )
        span["duration"] = max(ns - response.start, 0)
        inputs, input_truncated = _copy_messages_with_limits(response.inputs)
        outputs, output_truncated = _copy_messages_with_limits(response.output)
        span["meta"].update(model_name=session.model, model_provider=session.model_provider)
        span["meta"]["input"]["messages"] = inputs
        span["meta"]["output"]["messages"] = outputs
        span["meta"]["metadata"].update(
            turn_id=turn.turn_id, response_id=response_id, timing=response.timing, reasoning_effort=session.effort
        )
        if response.reasoning:
            span["meta"]["metadata"]["reasoning"] = _copy_reasoning_items(response.reasoning)
        if input_truncated or output_truncated:
            set_hidden_metadata(span, truncated_input=input_truncated, truncated_output=output_truncated)
        input_tokens, output_tokens = usage.get("input_tokens", 0), usage.get("output_tokens", 0)
        cached = usage.get("cached_input_tokens", 0)
        span["metrics"] = {
            **usage,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": usage.get("total_tokens", input_tokens + output_tokens),
            "cache_read_input_tokens": cached,
            "cache_write_input_tokens": 0,
            "non_cached_input_tokens": max(input_tokens - cached, 0),
        }
        span["metrics"].update(
            compute_cost_metrics(
                model_id=session.model,
                provider_id="openai",
                non_cached_input_tokens=max(input_tokens - cached, 0),
                cache_write_tokens=0,
                cache_read_tokens=cached,
                output_tokens=output_tokens,
                when=response.start,
            )
            or {}
        )
        response.llm, response.response_id = span, response_id
        response.usage = None
        response.inputs.clear()
        self._bounds(response.step, response.start, ns)
        turn.messages.extend(response.output)
        response.output = []
        if response_id:
            _remember(
                self._responses, (session.raw_session_id, response_id), (session, turn, response), RECENT_RESPONSES
            )
            pending = self._pending_proxy.pop(response_id, None)
            if pending:
                self._enrich(session, turn, response, pending[1])

    def _tool(
        self, session: CodexSession, turn: Turn, response: Response, item_id: str, name: str, arguments: Any, start: int
    ) -> Span:
        span = turn.tools.get(item_id)
        if span is None:
            active_agents = [agent for agent in turn.subagents.values() if agent["duration"] == 0]
            parent = active_agents[-1] if active_agents else response.step
            span = self._span(
                session, "tool", _display_tool_name(name, arguments), start, parent["span_id"], turn.root["trace_id"]
            )
            turn.tools[item_id] = span
        value, truncated = _truncate_text(_to_json_str(arguments), MAX_TOOL_VALUE_CHARS)
        span["meta"]["input"]["value"] = value
        span["meta"]["output"].setdefault("value", "")
        span["meta"]["metadata"].update(
            tool_id=item_id,
            raw_tool_name=name,
            status="running",
            input_format="json",
            output_format="verbatim",
            output_mime_type="text/plain",
            step_id=response.step["span_id"],
        )
        set_hidden_metadata(span, display={"input": "code", "output": "code"}, truncated_input=truncated)
        if f"tool_name:{span['name']}" not in span["tags"]:
            span["tags"].append(f"tool_name:{span['name']}")
        self._manifest(session, turn)
        return span

    def _manifest(self, session: CodexSession, turn: Turn) -> None:
        tools = sorted({span["name"] for span in turn.tools.values()})
        set_hidden_metadata(
            turn.root,
            agent_manifest={
                "name": self._config.agent_name,
                "instructions": "",
                "handoff_description": "",
                "model": session.model,
                "model_provider": session.model_provider,
                "model_settings": {"reasoning_effort": session.effort},
                "tools": [{"name": name} for name in tools],
                "handoffs": [],
                "guardrails": [],
            },
        )

    def _end_tool(self, turn: Turn, response: Response, span: Span, ns: int, output: Any, error: bool) -> None:
        value, truncated = _truncate_text(
            output if isinstance(output, str) else _to_json_str(output), MAX_TOOL_VALUE_CHARS
        )
        span["meta"]["output"]["value"] = value
        span["duration"] = max(ns - span["start_ns"], 0)
        span["status"] = "error" if error else "ok"
        span["meta"]["metadata"]["status"] = "failed" if error else "completed"
        messages = response.llm["meta"]["output"].get("messages", []) if response.llm else response.output
        for message in messages:
            for call in message.get("tool_calls", []):
                if call.get("id") in (span["meta"]["metadata"]["tool_id"], span["meta"]["metadata"].get("call_id")):
                    call["status"] = span["meta"]["metadata"]["status"]
        if error:
            span["meta"]["error"] = {"message": value or "Tool failed"}
        else:
            span["meta"].pop("error", None)
        if truncated:
            set_hidden_metadata(span, truncated_output=True)
        self._bounds(response.step, span["start_ns"], ns)
        if turn.closed:
            self._bounds(turn.root, span["start_ns"], ns)
        for approval in turn.root["meta"]["metadata"].get("_dd", {}).get("codex_approvals", []):
            if approval.get("call_id") in (
                span["meta"]["metadata"]["tool_id"],
                span["meta"]["metadata"].get("call_id"),
            ):
                approval.update(status=span["meta"]["metadata"]["status"], resolved_timestamp_ns=ns)

    def _item(self, session: CodexSession, turn: Turn, event: Dict[str, Any], ns: int) -> None:
        item = event.get("item") or {}
        item_id = str(item.get("id") or "")
        if not item_id:
            return
        completed = event.get("type") == "item_completed"
        if not completed and turn.closed:
            return
        interval = _item_interval(event, turn.root["start_ns"], ns)
        if item.get("type") in ("Reasoning", "AgentMessage"):
            if not turn.closed:
                turn.item_starts[item_id] = interval[0] if interval else ns
            return
        normalized = _tool_item(item)
        if normalized is None:
            return
        if item_id in turn.tools and turn.tools[item_id]["meta"]["metadata"].get("result_source") == "item_completed":
            return
        start, end = interval or (ns, ns)
        if not interval:
            duration = item.get("duration") or {}
            start = ns - int(duration.get("secs", 0)) * 1_000_000_000 - int(duration.get("nanos", 0))
            start = turn.item_starts.get(item_id, start)
        # Structured items do not always carry a response ID. Use the recorded
        # execution time within this explicit turn, never command-text equality.
        candidates = [r for r in turn.responses if r.start <= start]
        response = candidates[-1] if candidates else None
        if response is None:
            if turn.closed:
                return
            response = self._response(session, turn, start)
        direct = turn.calls.get(item_id)
        if direct:
            response = direct[0]
        existing = turn.tools.get(item_id)
        if existing:
            response = next(r for r in turn.responses if r.step["span_id"] == existing["meta"]["metadata"]["step_id"])
        name, arguments, output, details = normalized
        if existing is None and direct is None:
            # Older JSONL has both a direct call ID and a separate item ID.
            # Reuse a direct call only when its tool and arguments
            # identify one candidate in this response. Never inspect exec source.
            matches = [
                (call_response, call_span)
                for call_response, call_span in turn.calls.values()
                if call_span is not None
                and call_response is response
                and call_span["meta"]["metadata"].get("raw_tool_name") == name
                and call_span["meta"]["metadata"].get("result_source") != "item_completed"
                and _matches_tool_input(name, call_span["meta"]["input"].get("value", ""), arguments, session.cwd)
                and call_span["start_ns"] <= end
            ]
            if len(matches) == 1:
                response, existing = matches[0]
                assert existing is not None
                old_id = existing["meta"]["metadata"]["tool_id"]
                existing["meta"]["metadata"]["call_id"] = old_id
                turn.tools.pop(old_id, None)
                turn.tools[item_id] = existing
                if not interval:
                    start = min(start, existing["start_ns"])
        direct_input = (
            existing["meta"]["input"].get("value")
            if existing is not None and existing["meta"]["metadata"].get("call_id")
            else None
        )
        span = self._tool(session, turn, response, item_id, name, arguments, start)
        if direct_input is not None:
            span["meta"]["input"]["value"] = direct_input
        span["start_ns"] = start
        if not completed:
            turn.item_starts[item_id] = start
            return
        span["meta"]["metadata"].update(
            details,
            item_id=item_id,
            result_source="item_completed",
            timing="item_completed" if interval else "item_duration",
        )
        error = (
            _tool_status_is_error(item.get("status"))
            or bool(item.get("error"))
            or (isinstance(item.get("exit_code"), int) and item["exit_code"] != 0)
            or (isinstance(output, dict) and bool(output.get("isError")))
        )
        self._end_tool(turn, response, span, end, output, error)
        if turn.closed:
            self._attach_reviews(session, turn)

    def _context(self, session: CodexSession, payload: Dict[str, Any]) -> None:
        previous_cwd = session.cwd
        session.cwd = payload.get("cwd", session.cwd)
        session.model = payload.get("model", session.model)
        session.effort = payload.get("effort", session.effort)
        session.cli_version = payload.get("cli_version", session.cli_version)
        session.model_provider = payload.get("model_provider", session.model_provider)
        session.project_metadata = resolve_project_metadata(
            cwd=session.cwd,
            project_name=extract_agent_project_name(payload)
            or (session.project_metadata.project_name if session.cwd == previous_cwd else ""),
            git_repository_url=extract_git_repository_url(payload)
            or (session.project_metadata.git_repository_url if session.cwd == previous_cwd else ""),
        )
        turn = session.active_turn
        if turn is not None and not turn.closed:
            turn.root["meta"]["model_name"] = session.model
            turn.root["meta"]["metadata"].update(cwd=session.cwd, reasoning_effort=session.effort)
            apply_project_metadata_to_span(turn.root, session.project_metadata)

    def _group(self, child_id: str, session: CodexSession) -> None:
        _remember(self._child_session_ids, child_id, session.session_id, RECENT_TURNS)
        child = self._sessions.get(child_id)
        if child:
            child.session_id = session.session_id
        shared = self._hooks_api._sessions.get(child_id)
        if shared:
            shared.session_id = session.session_id
            parent = self._hooks_api._sessions[session.raw_session_id]
            shared.session_name = parent.session_name
        for span in self._hooks_api._assembled_spans:
            if span.get("session_id") == child_id:
                span["session_id"] = session.session_id
                span["tags"] = [tag for tag in span.get("tags", []) if not tag.startswith("session_id:")]
                span["tags"].append(f"session_id:{session.session_id}")
                metadata = span.setdefault("meta", {}).setdefault("metadata", {})
                metadata.pop("session_name", None)
                parent_name = self._hooks_api._sessions[session.raw_session_id].session_name
                if parent_name:
                    metadata["session_name"] = parent_name
        self._hooks_api._synchronize_session_tags(session.session_id)

    def _review(self, sid: str, record: Dict[str, Any]) -> None:
        # Review sessions are annotations, not user turns. Retain only a bounded
        # summary and explicit source identity.
        payload = record["payload"]
        state = self._reviews.setdefault(sid, {})
        # A cursor may start at task_started, before review identity is supplied
        # by turn_context. Remove only empty turns created before that identity.
        for key, (_, turn) in list(self._turns.items()):
            if key[0] == sid and not turn.root["meta"]["input"]["value"] and not turn.tools:
                state.update(
                    start_ns=turn.root["start_ns"],
                    turn_id=turn.turn_id,
                    parent_turn_id=turn.root["meta"]["metadata"].get("parent_turn_id", ""),
                )
                del self._turns[key]
                self._hooks_api._assembled_spans[:] = [
                    span for span in self._hooks_api._assembled_spans if span["trace_id"] != turn.root["trace_id"]
                ]
                self._sessions.pop(sid, None)
                self._hooks_api._sessions.pop(sid, None)
        while len(self._reviews) > RECENT_TURNS:
            self._reviews.popitem(last=False)
        if record["type"] == "session_meta":
            state["parent"] = payload.get("parent_thread_id", "")
        if payload.get("type") == "task_started":
            parent = state.get("parent", "")
            state.clear()
            state.update(
                parent=parent,
                turn_id=payload.get("turn_id", ""),
                parent_turn_id=(payload.get("turn_attribution") or {}).get("parent_turn_id")
                or payload.get("root_turn_id", ""),
                start_ns=_timestamp_to_ns(record.get("timestamp", "")),
            )
        if payload.get("model"):
            state["model"] = payload["model"]
        if payload.get("type") == "message" and payload.get("role") == "assistant":
            try:
                state["decision"] = json.loads(_content_text(payload.get("content")))
            except ValueError:
                pass
        if record["type"] == "token_usage_record":
            state["usage"] = payload.get("usage", {})
        if payload.get("type") == "token_count" and not state.get("usage"):
            state["usage"] = (payload.get("info") or {}).get("last_token_usage", {})
        if payload.get("type") == "task_complete":
            parent_key = (
                str(state.get("parent") or ""),
                str(state.get("parent_turn_id") or payload.get("root_turn_id") or ""),
            )
            review_key = (*parent_key, sid, str(state.get("turn_id") or ""))
            review = {**state, "review_session_id": sid, "end_ns": _timestamp_to_ns(record.get("timestamp", ""))}
            _remember(self._pending_reviews, review_key, (time.monotonic(), review), RECENT_TURNS)
            parent_turn = self._turns.get(parent_key)
            if parent_turn:
                self._attach_reviews(*parent_turn)
            elif not parent_key[0]:
                matches = [entry for (parent_sid, tid), entry in self._turns.items() if tid == parent_key[1]]
                if len(matches) == 1:
                    self._attach_reviews(*matches[0])

    def _attach_reviews(self, session: CodexSession, turn: Turn) -> None:
        # Wait for the turn's tool set before deciding whether the timing match
        # is unique. A review has parent turn identity, but no tool ID in JSONL.
        if not turn.closed:
            return
        for key, (_, review) in list(self._pending_reviews.items()):
            if key[1] != turn.turn_id or (key[0] and key[0] != session.raw_session_id):
                continue
            if not key[0] and sum(tid == turn.turn_id for _, tid in self._turns) != 1:
                continue
            start, end = review.get("start_ns", 0), review["end_ns"]
            candidates = [
                span
                for span in turn.tools.values()
                if start > 0
                and end >= start
                and span["meta"]["metadata"].get("status") in ("completed", "failed")
                and span["start_ns"] <= start
                and end <= span["start_ns"] + span["duration"]
            ]
            if len(candidates) != 1:
                continue
            span = candidates[0]
            decision = review.get("decision")
            if not isinstance(decision, dict):
                continue
            usage = dict(review.get("usage", {}))
            model = review.get("model") or ""
            cost = compute_cost_metrics(
                model_id=model,
                provider_id="openai",
                non_cached_input_tokens=max(usage.get("input_tokens", 0) - usage.get("cached_input_tokens", 0), 0),
                cache_write_tokens=usage.get("cache_write_input_tokens", 0),
                cache_read_tokens=usage.get("cached_input_tokens", 0),
                output_tokens=usage.get("output_tokens", 0),
                when=start,
            )
            usage.update(
                estimated_total_cost=cost["estimated_total_cost"] if cost else None,
                estimated_total_cost_usd=cost["estimated_total_cost"] / 1_000_000_000 if cost else None,
                estimated_cost_model=model if cost else None,
            )
            entry = {
                "review_session_id": review["review_session_id"],
                "model": model,
                "outcome": decision.get("outcome", ""),
                "risk_level": decision.get("risk_level", ""),
                "explanation": decision.get("rationale") or decision.get("explanation") or "",
                "usage": usage,
                "tool_id": span["meta"]["metadata"]["tool_id"],
            }
            existing = span["meta"]["metadata"].get("_dd", {}).get("auto_reviews", [])
            set_hidden_metadata(span, auto_reviews=existing + [entry])
            del self._pending_reviews[key]

    def _dispatch(
        self, session_id: str, record: Dict[str, Any], proxy_session_key: Optional[str] = None
    ) -> List[CompletedTrace]:
        if not isinstance(record, dict) or not isinstance(record.get("payload"), dict):
            return []
        self._expire()
        fingerprint = hashlib.sha256(json.dumps([session_id, record], sort_keys=True).encode()).digest()
        if fingerprint in self._seen:
            return []
        kind, payload = str(record.get("type") or ""), record["payload"]
        event = _event_type(kind, payload)
        ns = _timestamp_to_ns(record.get("timestamp", ""))
        if (
            payload.get("thread_source") == "guardian_review"
            or (payload.get("turn_attribution") or {}).get("turn_trigger") == "guardian_review"
            or payload.get("model") == "codex-auto-review"
            or session_id in self._reviews
        ):
            self._review(session_id, record)
            _remember(self._seen, fingerprint, True, RECENT_RECORDS)
            return []
        session = self._session(session_id)
        session.last_seen = time.monotonic()
        if proxy_session_key:
            self._hooks_api._register_session_token(proxy_session_key, session_id)
        if kind in ("session_meta", "turn_context"):
            self._context(session, {**record, **payload})
        if kind == "session_meta":
            parent = payload.get("parent_thread_id")
            if parent in self._sessions:
                self._group(session_id, self._sessions[parent])
        if event == "session_name":
            if session.session_id == session_id:
                self._hooks_api._set_session_name(self._hooks_api._sessions[session_id], str(payload.get("name") or ""))
            return []
        turn_id = str(payload.get("turn_id") or (payload.get("id") if event == "start" else "") or "")
        if turn_id and any(tid == turn_id and sid != session_id for sid, tid in self._turns):
            session.replayed_turn = True
            return []  # Forked transcripts can replay their parent's task IDs.
        if turn_id:
            session.replayed_turn = False
        if session.replayed_turn:
            return []
        turn = self._turns.get((session_id, turn_id), (None, None))[1] if turn_id else session.active_turn
        completed: List[CompletedTrace] = []
        if event == "start":
            turn, completed = self._start(session, turn_id or str(payload.get("id") or _format_span_id()), ns)
            parent_turn_id = (payload.get("turn_attribution") or {}).get("parent_turn_id") or payload.get(
                "root_turn_id"
            )
            if parent_turn_id and parent_turn_id != turn.turn_id:
                turn.root["meta"]["metadata"]["parent_turn_id"] = parent_turn_id
        elif event == "prompt":
            message = payload.get("message", "") if kind == "event_msg" else _content_text(payload.get("content"))
            normalized_message = " ".join(str(message).split())
            # Codex can record one prompt in both formats. Only collapse the pair.
            if (
                turn
                and not turn.closed
                and normalized_message
                and turn.last_prompt == (normalized_message, "response_item" if kind == "event_msg" else "event_msg")
            ):
                turn.last_prompt = None
            else:
                if turn is None or turn.closed or turn.root["meta"]["input"]["value"]:
                    turn, completed = self._start(
                        session, turn_id or _format_span_id(), ns, provisional=not bool(turn_id)
                    )
                turn.messages.append({"role": "user", "content": message})
                turn.root["meta"]["input"]["value"] = message
                turn.last_prompt = (normalized_message, kind)
        elif turn is not None:
            turn.last_ns = max(turn.last_ns, ns)
            completed = self._apply_event(session, turn, event, payload, ns)
        _remember(self._seen, fingerprint, True, RECENT_RECORDS)
        return completed

    def _apply_event(
        self, session: CodexSession, turn: Turn, event: str, payload: Dict[str, Any], ns: int
    ) -> List[CompletedTrace]:
        # Only recorded tool items may update a closed turn.
        if event == "item":
            self._item(session, turn, payload, ns)
        elif turn.closed:
            return []
        elif event in ("usage", "token_count"):
            if event == "token_count" and (turn.current is None or (not payload.get("info") and not turn.modern_usage)):
                self._response(session, turn, ns)
            self._usage(session, turn, payload, ns, event == "usage")
        elif event == "model":
            self._model_item(session, turn, payload, ns)
        elif event in ("agent_message", "finish"):
            message = payload.get("last_agent_message" if event == "finish" else "message", "")
            if message:
                turn.root["meta"]["output"]["value"] = message
                if turn.current:
                    turn.current.step["meta"]["output"]["value"] = message
                    if turn.current.llm is None:
                        self._model_item(session, turn, {"type": "message", "content": message}, ns)
            if event == "finish":
                return self._finish(session, turn, ns, "error" if payload.get("type") == "turn_aborted" else "ok")
        elif event == "tool_output":
            call_id = str(payload.get("call_id") or "")
            call = turn.calls.get(call_id)
            if call:
                response, span = call
                output = payload.get("output", "")
                if span is not None and span["meta"]["metadata"].get("result_source") != "item_completed":
                    self._end_tool(turn, response, span, ns, output, _tool_status_is_error(payload.get("status")))
                turn.messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": call_id,
                        "content": _to_json_str(output),
                        "status": span["meta"]["metadata"]["status"] if span else "completed",
                    }
                )
        elif event == "tool_result":
            response = self._response(session, turn, ns)
            item_id = str(payload.get("call_id") or payload.get("id") or _format_span_id())
            search = payload.get("type") == "web_search_call"
            name = "web_search" if search else "apply_patch"
            args = payload.get("action", payload.get("query", "")) if search else payload.get("changes", {})
            span = self._tool(session, turn, response, item_id, name, args, ns)
            self._end_tool(
                turn,
                response,
                span,
                ns,
                payload.get("stdout", "") + payload.get("stderr", ""),
                payload.get("success") is False or _tool_status_is_error(payload.get("status")),
            )
        elif event == "subagent":
            self._subagent(session, turn, payload, ns)
        elif event == "compaction":
            target = turn.current.step if turn.current else turn.root
            entries = target["meta"]["metadata"].get("_dd", {}).get("compactions", [])
            set_hidden_metadata(
                target, compactions=entries + [{"trigger": payload.get("type") or "compacted", "timestamp_ns": ns}]
            )
        elif event == "approval":
            entries = turn.root["meta"]["metadata"].get("_dd", {}).get("codex_approvals", [])
            approval = {
                **payload,
                "tool": "apply_patch" if payload.get("type") == "apply_patch_approval_request" else "exec_command",
                "input": _to_json_str(payload.get("command", payload.get("reason", ""))),
                "timestamp_ns": ns,
                "status": "pending",
            }
            set_hidden_metadata(turn.root, codex_approvals=entries + [approval])
        return []

    def _subagent(self, session: CodexSession, turn: Turn, payload: Dict[str, Any], ns: int) -> None:
        call_id = str(payload.get("call_id") or "")
        nickname = payload.get("new_agent_nickname") or payload.get("agent_nickname") or ""
        if payload.get("type") == "collab_agent_spawn_begin":
            response = self._response(session, turn, ns)
            span = self._span(
                session, "agent", nickname or "subagent", ns, response.step["span_id"], turn.root["trace_id"]
            )
            span["meta"]["input"]["value"] = payload.get("prompt", "")
            span["tags"].append("subagent:true")
            span["meta"]["metadata"]["subagent"] = {
                "call_id": call_id,
                "sender_thread_id": payload.get("sender_thread_id", ""),
                "agent_nickname": nickname or "subagent",
            }
            turn.subagents[call_id] = span
        elif call_id in turn.subagents:
            span = turn.subagents[call_id]
            span["duration"] = max(ns - span["start_ns"], 0)
            span["status"] = "error" if _tool_status_is_error(payload.get("status")) else "ok"
            span["meta"]["metadata"]["subagent"].update(
                {
                    **payload,
                    "child_session_id": payload.get("new_thread_id", ""),
                    "agent_nickname": nickname or span["meta"]["metadata"]["subagent"]["agent_nickname"],
                    "agent_role": payload.get("new_agent_role", ""),
                }
            )
            if payload.get("new_thread_id"):
                self._group(payload["new_thread_id"], session)
            if nickname:
                span["name"] = nickname

    def _enrich(self, session: CodexSession, turn: Turn, response: Response, proxy: Span) -> None:
        span = response.llm
        if span is None:
            return
        identity = {key: span[key] for key in ("span_id", "trace_id", "parent_id", "session_id")}
        metadata = {**span["meta"]["metadata"], **proxy["meta"]["metadata"]}
        forwarded = "lapdog_forwarded:true" in span["tags"]
        span.update(proxy)
        span.update(identity)
        span["tags"] = self._hooks_api.base_tags(
            session, source="codex-proxy", ml_app=self._config.ml_app, user_handle=self._config.user_handle
        )
        span["meta"]["metadata"] = {**metadata, "turn_id": turn.turn_id, "timing": "proxy"}
        if forwarded:
            span["tags"].append("lapdog_forwarded:true")
        apply_project_metadata_to_span(span, session.project_metadata)
        self._hooks_api._apply_registered_session_tags(span)
        self._bounds(response.step, span["start_ns"], span["start_ns"] + span["duration"])
        if turn.closed:
            self._bounds(turn.root, span["start_ns"], span["start_ns"] + span["duration"])

    def register_proxy_llm_span(self, maybe_session_id: Optional[str], span: Span, start_ns: int, end_ns: int) -> None:
        self._expire()
        response_id = str(span.get("meta", {}).get("metadata", {}).get("response_id") or "")
        matches = [entry for (sid, rid), entry in self._responses.items() if rid == response_id]
        if response_id and len(matches) == 1:
            self._enrich(*matches[0], span)
        elif response_id:
            _remember(self._pending_proxy, response_id, (time.monotonic(), span), RECENT_RESPONSES)
        # An unmatched response is not classified as a title and never discarded
        # based on text. It remains available through /codex/hooks/raw-proxy.

    async def handle_hook(self, request: Request) -> web.Response:
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)
        if not isinstance(body, dict):
            return web.json_response({"error": "JSON body must be an object"}, status=400)
        record = body.get("record", body)
        if not isinstance(record, dict) or not isinstance(record.get("payload"), dict):
            return web.json_response({"error": "a JSONL record is required"}, status=400)
        sid = body.get("session_id") or (
            record.get("payload", {}).get("id") if record.get("type") == "session_meta" else None
        )
        if not sid and len(self._sessions) == 1:
            sid = next(iter(self._sessions))
        if not isinstance(sid, str) or not sid:
            return web.json_response({"error": "session_id and a JSONL record are required"}, status=400)
        completed = self._dispatch(sid, record, body.get("proxy_session_key"))
        raw = dict(body)
        raw.pop("proxy_session_key", None)
        self._raw_events.append(raw)
        if body.get("backfill") is not True:
            for completed_sid, trace_id in completed:
                await self._hooks_api._forward_trace_to_backend(completed_sid, trace_id=trace_id, span_source="Codex")
                await self._hooks_api._forward_eval_metrics_to_backend(completed_sid, trace_id=trace_id)
        return web.json_response({"status": "ok"})

    async def handle_raw_events(self, request: Request) -> web.Response:
        return web.json_response({"events": list(self._raw_events)})

    async def handle_raw_proxy(self, request: Request) -> web.Response:
        self._expire()
        return web.json_response({"spans": [span for _, span in self._pending_proxy.values()]})

    def get_routes(self) -> List[web.RouteDef]:
        return [
            web.post("/codex/hooks", with_cors(self.handle_hook)),
            web.get("/codex/hooks/raw", with_cors(self.handle_raw_events)),
            web.get("/codex/hooks/raw-proxy", with_cors(self.handle_raw_proxy)),
        ]
