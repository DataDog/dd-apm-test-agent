"""Codex lifecycle capture, keyed by runtime invocation and agent IDs.

The transcript adapter supplies LLM history only. Tool spans never depend on
JavaScript source, printed results, or the order of concurrent tool calls.
"""

import datetime
import json
from typing import Any
from typing import Dict
from typing import List
from typing import TYPE_CHECKING
from typing import Tuple

from aiohttp import web

from ddapm_test_agent.cors import with_cors
from lapdog.claude_hooks import PendingToolSpan
from lapdog.claude_hooks import _format_span_id
from lapdog.claude_hooks import _to_json_str
from lapdog.codex_exec import display_tool_name
from lapdog.codex_hook import EVENTS
from lapdog.utils import set_hidden_metadata

if TYPE_CHECKING:
    from lapdog.codex_hooks import CodexHooksAPI


def tool_result(name: str, response: Any) -> Tuple[Any, bool]:
    """Normalize the documented Bash envelope without discarding its fields."""
    if isinstance(response, str):
        try:
            parsed = json.loads(response)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            response = parsed
    if not isinstance(response, dict):
        return response, False
    error = bool(response.get("isError") or response.get("error"))
    if name == "Bash":
        response = dict(response)
        if "output" not in response:
            response["output"] = str(response.get("stdout") or "") + str(response.get("stderr") or "")
        exit_code = response.get("exit_code", response.get("exitCode"))
        if exit_code is not None:
            response["exit_code"] = exit_code
        error = error or bool(response.get("interrupted")) or (isinstance(exit_code, int) and exit_code != 0)
    return response, error


class CodexLifecycle:
    def __init__(self, api: "CodexHooksAPI") -> None:
        self.api = api
        self.cursors: Dict[str, int] = {}
        self.live_paths: set[str] = set()
        self.events: set[str] = set()
        self.tools: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
        self.agents: Dict[str, Dict[str, Any]] = {}
        self.agent_details: Dict[str, Dict[str, Any]] = {}
        self.spawn_requests: Dict[Tuple[str, str], Dict[str, Any]] = {}

    async def cursor(self, request: web.Request) -> web.Response:
        return web.json_response({"offset": self.cursors.get(request.query.get("path", ""), 0)})

    async def handle(self, request: web.Request) -> web.Response:
        try:
            body = await request.json()
        except ValueError:
            return web.json_response({"error": "invalid JSON"}, status=400)
        if not isinstance(body, dict) or not isinstance(body.get("session_id"), str) or not body["session_id"]:
            return web.json_response({"error": "missing session_id"}, status=400)
        records = body.get("records", [])
        hook = body.get("hook")
        if not isinstance(records, list) or any(not isinstance(r, dict) for r in records):
            return web.json_response({"error": "records must be objects"}, status=400)
        if hook is not None and (not isinstance(hook, dict) or hook.get("hook_event_name") not in EVENTS):
            return web.json_response({"error": "unsupported hook"}, status=400)
        event_id = body.get("event_id")
        if hook is not None and (not isinstance(event_id, str) or not event_id):
            return web.json_response({"error": "missing event_id"}, status=400)
        path = body.get("path", "")
        offset, end = body.get("offset", 0), body.get("end_offset", 0)
        if not isinstance(path, str) or type(offset) is not int or type(end) is not int or not 0 <= offset <= end:
            return web.json_response({"error": "invalid cursor"}, status=400)
        # No awaits between cursor validation and commit: concurrent hook processes
        # retry a stale batch instead of applying it twice or losing later records.
        if path and self.cursors.get(path, 0) != offset:
            return web.json_response({"error": "stale cursor"}, status=409)
        sid = body["session_id"]
        session = self.api._get_or_create_session(sid, 0)
        session.native_capture = True
        token = body.get("proxy_session_key")
        if isinstance(token, str) and token:
            session.proxy_session_keys.add(token)
            self.api._hooks_api._register_session_token(token, sid)
        completed = []
        for record in records:
            if body.get("initial_context") and path not in self.live_paths:
                payload = record.get("payload", {})
                turn_id = payload.get("turn_id") or payload.get("id")
                starts_turn = record.get("type") == "turn_context" or (
                    record.get("type") == "event_msg" and payload.get("type") == "task_started"
                )
                if starts_turn and turn_id and turn_id == body.get("capture_turn_id"):
                    self.live_paths.add(path)
                else:
                    # Prime session/model metadata without replaying old turns.
                    # The explicit backfill endpoint still assembles history.
                    if record.get("type") == "session_meta" or (
                        record.get("type") == "event_msg" and payload.get("type") == "session_name"
                    ):
                        self.api._dispatch(sid, record)
                    elif record.get("type") == "turn_context" and session.active_turn is None:
                        self.api._apply_turn_context(session, record)
                    continue
            completed.extend(self.ingest(sid, record, body.get("proxy_session_key")))
        if path:
            self.cursors[path] = end
        if hook is not None:
            if event_id not in self.events:
                self.events.add(str(event_id))
                self.api._raw_events.append({"session_id": sid, "hook": hook})
                completed.extend(self.dispatch(sid, hook))
        self.link_child(sid)
        for session_id, trace_id in (dict.fromkeys(completed) if not body.get("backfill") else {}):
            await self.api._hooks_api._forward_trace_to_backend(session_id, trace_id=trace_id, span_source="Codex")
            await self.api._hooks_api._forward_eval_metrics_to_backend(session_id, trace_id=trace_id)
        return web.json_response({"status": "ok", "offset": end})

    def link_child(self, sid: str) -> None:
        agent = self.agents.get(sid)
        session = self.api._sessions.get(sid)
        if agent and session and session.active_turn and session.active_turn.root_span_ref:
            root = session.active_turn.root_span_ref
            root["span_links"] = [
                {
                    "span_id": agent["span_id"],
                    "trace_id": agent["trace_id"],
                    "attributes": {"from": "output", "to": "input"},
                }
            ]
            root["meta"]["metadata"]["parent_agent_id"] = sid

    def enrich_agent(self, agent_id: str) -> None:
        span = self.agents.get(agent_id)
        details = self.agent_details.get(agent_id)
        if span is None or details is None:
            return
        span["meta"]["input"]["value"] = details.get("prompt", "")
        nickname = details.get("new_agent_nickname")
        if nickname:
            span["name"] = nickname
        span["meta"]["metadata"]["subagent"].update(
            {
                "child_session_id": agent_id,
                "agent_role": details.get("new_agent_role", ""),
            }
        )

    def ingest(self, sid: str, record: Dict[str, Any], token: Any = None) -> List[Tuple[str, str]]:
        session = self.api._sessions.get(sid)
        if session is None or sid in self.api._auto_review_sessions:
            return self.api._dispatch(sid, record, proxy_session_key=token)
        turn = session.active_turn
        payload = record.get("payload", {})
        kind = payload.get("type")
        if kind == "collab_agent_spawn_begin":
            self.spawn_requests[(sid, payload.get("call_id", ""))] = payload
        elif kind == "collab_agent_spawn_end" and payload.get("new_thread_id"):
            agent_id = payload["new_thread_id"]
            begin = self.spawn_requests.pop((sid, payload.get("call_id", "")), {})
            self.agent_details[agent_id] = {**begin, **payload}
            self.enrich_agent(agent_id)
        starts_turn = (
            record.get("type") == "turn_context"
            or kind in ("task_started", "user_message")
            or (kind == "message" and payload.get("role") == "user")
        )
        # A Stop hook can precede the final transcript flush. Enrich its closed
        # turn rather than creating a phantom turn for a late token/message row.
        late = turn is not None and turn.closed and not starts_turn
        if late and turn is not None:
            turn.closed = False
        try:
            completed = self.api._dispatch(sid, record, proxy_session_key=token)
        finally:
            if late and turn is not None:
                turn.closed = True
        if late and turn is not None:
            completed.append((session.session_id, turn.trace_id))
        return completed

    def dispatch(self, sid: str, hook: Dict[str, Any]) -> List[Tuple[str, str]]:
        from lapdog.codex_hooks import _timestamp_to_ns

        event = hook["hook_event_name"]
        record: Dict[str, Any] = {
            "type": "native_hook",
            "timestamp": hook.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "payload": hook,
        }
        ns = _timestamp_to_ns(record["timestamp"])
        session = self.api._get_or_create_session(sid, ns)
        session.native_capture = True
        session.cwd = hook.get("cwd") or session.cwd
        session.model = hook.get("model") or session.model
        self.api._handle_session_meta(session, {**record, "payload": {"cwd": session.cwd, "originator": "codex-hooks"}})
        completed: List[Tuple[str, str]] = []
        if event == "SessionStart":
            return completed
        if event == "SubagentStop":
            span = self.agents.get(hook.get("agent_id", ""))
            if span is not None:
                span["duration"] = max(0, ns - span["start_ns"])
                span["meta"]["output"]["value"] = hook.get("last_assistant_message") or ""
                span["meta"]["metadata"]["subagent"]["status"] = "completed"
            return completed
        if event in ("Stop", "Interrupt", "SessionEnd"):
            turn = session.active_turn
            if turn is None or turn.closed:
                return completed
            message = hook.get("last_assistant_message")
            if message and turn.root_span_ref:
                turn.root_span_ref["meta"]["output"]["value"] = message
            # Stop may request continuation, so it is a turn boundary, not a
            # permanent session boundary. A subsequent turn starts normally.
            return self.api._finalize_turn(session, status="error" if event == "Interrupt" else "ok", end_ns=ns)
        turn_id = hook.get("turn_id")
        if (
            event != "SubagentStart"
            and turn_id
            and (session.active_turn is None or session.active_turn.turn_id != turn_id)
        ):
            completed.extend(self.api._start_turn(session, record))
        turn = self.api._active_turn(session, record)
        self.api._ensure_step(session, turn, ns)
        self.api._update_last_ns(session, record)
        if event == "UserPromptSubmit":
            if turn.root_span_ref and not session.user_prompts:
                turn.root_span_ref["meta"]["input"]["value"] = hook.get("prompt", "")
        elif event in ("PreToolUse", "PostToolUse"):
            tool_id = hook.get("tool_use_id")
            if not isinstance(tool_id, str) or not tool_id:
                return completed
            key = (sid, str(turn_id or turn.turn_id), tool_id)
            entry = self.tools.get(key)
            if entry is None:
                name = hook.get("tool_name", "unknown")
                arguments = hook.get("tool_input", {})
                if name == "Bash" and isinstance(arguments, dict):
                    display = display_tool_name("exec_command", {"cmd": arguments.get("command", "")})
                else:
                    display = display_tool_name(name, arguments)
                pending = PendingToolSpan(_format_span_id(), display, arguments, turn.step_span_id, ns)
                pending_id = f"native:{turn.turn_id}:{tool_id}"
                session.pending_tools[pending_id] = pending
                session.pending_tool_ids_by_span_id[pending.span_id] = pending_id
                entry = {"pending": pending, "pending_id": pending_id, "name": name, "span": None}
                self.tools[key] = entry
                session.tools_used.add(display)
            pending = entry["pending"]
            if event == "PreToolUse":
                pending.start_ns = min(pending.start_ns, ns)
                if entry["span"] is not None:
                    tool_span = entry["span"]
                    end_ns = tool_span["start_ns"] + tool_span["duration"]
                    tool_span["start_ns"] = pending.start_ns
                    tool_span["duration"] = max(0, end_ns - pending.start_ns)
                return completed
            if entry["span"] is not None:
                return completed
            value, error = tool_result(entry["name"], hook.get("tool_response", ""))
            session.pending_tools.pop(entry["pending_id"], None)
            details: Dict[str, Any] = {}
            if entry.get("permission_request"):
                details["_dd"] = {"permission_request": entry["permission_request"]}
            if isinstance(value, dict) and entry["name"] != "Bash":
                content = value.get("content")
                if (
                    isinstance(content, list)
                    and len(content) == 1
                    and isinstance(content[0], dict)
                    and content[0].get("type") == "text"
                ):
                    details["response_metadata"] = {k: v for k, v in value.items() if k != "content"}
                    value = content[0].get("text", "")
                    if isinstance(value, str):
                        try:
                            value = json.loads(value)
                        except ValueError:
                            pass
            entry["span"] = self.api._emit_tool_span(
                session,
                pending,
                ns,
                _to_json_str(value),
                error,
                extra_metadata={
                    **details,
                    "hook_tool_use_id": tool_id,
                    "raw_tool_name": "exec_command" if entry["name"] == "Bash" else entry["name"],
                    "capture_source": "codex-hooks",
                    "result_matched": True,
                    "result_source": "PostToolUse",
                },
            )
            self.api._attach_pending_auto_reviews(session)
            self.api._update_agent_manifest(session)
        elif event == "PermissionRequest":
            # A request is not proof that approval was granted. Attach by exact
            # runtime input only when there is one candidate; never pick child 0.
            arguments = hook.get("tool_input", {})
            request_data = {"tool_name": hook.get("tool_name"), "input": arguments}
            if isinstance(arguments, dict) and isinstance(arguments.get("description"), str):
                request_data["justification"] = arguments["description"]
            candidates = []
            for (owner, owner_turn, _), entry in self.tools.items():
                if owner != sid or owner_turn != str(turn_id or turn.turn_id) or entry["span"] is not None:
                    continue
                original = entry["pending"].tool_input
                matches = original == arguments
                if hook.get("tool_name") == "Bash" and isinstance(original, dict) and isinstance(arguments, dict):
                    matches = original.get("command") == arguments.get("command")
                if entry["name"] == hook.get("tool_name") and matches:
                    candidates.append(entry)
            if len(candidates) == 1:
                candidates[0]["permission_request"] = request_data
            else:
                target = turn.step_span_ref or turn.root_span_ref
                if target is not None:
                    target["meta"]["metadata"].setdefault("_dd", {}).setdefault("permission_requests", []).append(
                        request_data
                    )
        elif event in ("PreCompact", "PostCompact"):
            self.api._handle_compaction(session, record, trigger=event)
        elif event == "SubagentStart":
            agent_id = hook.get("agent_id")
            if not isinstance(agent_id, str) or not agent_id or agent_id in self.agents:
                return completed
            self.agents[agent_id] = self.api._handle_collab_agent_spawn_begin(
                session,
                record,
                {
                    "call_id": agent_id,
                    "new_agent_nickname": hook.get("agent_type", "subagent"),
                    "sender_thread_id": sid,
                },
            )
            self.api._set_session_group(agent_id, session.session_id)
            set_hidden_metadata(self.agents[agent_id], capture_source="codex-hooks")
            self.enrich_agent(agent_id)
            self.link_child(agent_id)
        return completed

    def routes(self) -> List[web.RouteDef]:
        return [
            web.get("/codex/hooks/cursor", with_cors(self.cursor)),
            web.post("/codex/hooks/native", with_cors(self.handle)),
        ]
