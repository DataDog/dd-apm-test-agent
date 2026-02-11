"""Claude Code Hooks → LLM Observability Spans.

Receives Claude Code lifecycle hook events via HTTP and assembles them
into LLMObs-format spans that can be queried through the Event Platform APIs.
"""

import gzip
import json
import logging
import os
import random
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Set

from aiohttp import ClientSession
from aiohttp import web
from aiohttp.web import Request

import msgpack

from .claude_link_tracker import ClaudeLinkTracker
from .llmobs_event_platform import with_cors


log = logging.getLogger(__name__)


class PendingToolSpan:
    """Tracks a tool invocation between PreToolUse and PostToolUse."""

    def __init__(self, span_id: str, tool_name: str, tool_input: Any, parent_id: str, start_ns: int) -> None:
        self.span_id = span_id
        self.tool_name = tool_name
        self.tool_input = tool_input
        self.parent_id = parent_id
        self.start_ns = start_ns


class SessionState:
    """Tracks the state of a single Claude Code session."""

    def __init__(self, session_id: str, trace_id: str, root_span_id: str, start_ns: int) -> None:
        self.session_id = session_id
        self.trace_id = trace_id
        self.root_span_id = root_span_id
        self.start_ns = start_ns
        self.agent_span_stack: List[Dict[str, Any]] = []
        self.pending_tools: Dict[str, PendingToolSpan] = {}
        self.user_prompts: List[str] = []
        self.model: str = ""
        self.tools_used: Set[str] = set()
        self.root_span_emitted: bool = False
        # Deferred agent spans waiting for PostToolUse(Task) to provide their output.
        # Keyed by tool_use_id of the Task tool that spawned the subagent.
        self.deferred_agent_spans: Dict[str, Dict[str, Any]] = {}


_MAX_UINT_64 = (1 << 64) - 1


def _rand64bits() -> int:
    """Generate a random 64-bit unsigned integer."""
    return random.getrandbits(64)


def _rand128bits() -> int:
    """Generate a 128-bit trace ID matching Datadog's format: <32-bit unix seconds><32 zero bits><64 random bits>."""
    return int(time.time()) << 96 | _rand64bits()


def _format_span_id() -> str:
    """Generate a span ID as a decimal string of a random 64-bit unsigned int."""
    return str(_rand64bits())


def _format_trace_id() -> str:
    """Generate a trace ID matching Datadog's format_trace_id: 32-char hex for 128-bit IDs."""
    trace_id = _rand128bits()
    if trace_id > _MAX_UINT_64:
        return "{:032x}".format(trace_id)
    return str(trace_id)


def _is_user_prompt_entry(entry: Dict[str, Any]) -> bool:
    """Check if a transcript entry is an actual user prompt (not a tool_result)."""
    if entry.get("type") != "user":
        return False
    content = entry.get("message", {}).get("content", [])
    if isinstance(content, str):
        return True
    if isinstance(content, list):
        return any(isinstance(b, dict) and b.get("type") == "text" for b in content)
    return False


def _read_console_output(transcript_path: str) -> str:
    """Read assistant text responses after the last user prompt from a Claude Code transcript JSONL file."""
    if not transcript_path or not os.path.isfile(transcript_path):
        return ""
    try:
        entries: List[Dict[str, Any]] = []
        with open(transcript_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

        # Find the last actual user prompt (not tool_result entries)
        last_prompt_idx = -1
        for i, entry in enumerate(entries):
            if _is_user_prompt_entry(entry):
                last_prompt_idx = i

        # Collect assistant text after the last user prompt
        responses: List[str] = []
        start = last_prompt_idx + 1 if last_prompt_idx >= 0 else 0
        for entry in entries[start:]:
            if entry.get("type") == "assistant":
                for block in entry.get("message", {}).get("content", []):
                    if isinstance(block, dict) and block.get("type") == "text":
                        text = block["text"].strip()
                        if text:
                            responses.append(text)
        return "\n\n".join(responses)
    except Exception as e:
        log.debug("Failed to read transcript %s: %s", transcript_path, e)
        return ""


class ClaudeHooksAPI:
    """Handler for Claude Code hook events."""

    def __init__(self, link_tracker: Optional[ClaudeLinkTracker] = None) -> None:
        self._sessions: Dict[str, SessionState] = {}
        self._assembled_spans: List[Dict[str, Any]] = []
        self._raw_events: List[Dict[str, Any]] = []
        self._link_tracker = link_tracker
        self._app: Optional[web.Application] = None

    def set_app(self, app: web.Application) -> None:
        """Set the aiohttp app reference for backend forwarding."""
        self._app = app

    def _get_or_create_session(self, session_id: str) -> SessionState:
        """Get existing session or create a new one."""
        if session_id not in self._sessions:
            trace_id = _format_trace_id()
            root_span_id = _format_span_id()
            now_ns = int(time.time() * 1_000_000_000)
            self._sessions[session_id] = SessionState(
                session_id=session_id,
                trace_id=trace_id,
                root_span_id=root_span_id,
                start_ns=now_ns,
            )
        return self._sessions[session_id]

    def _current_parent_id(self, session: SessionState) -> str:
        """Return the span_id of the current active agent (top of stack), or root."""
        if session.agent_span_stack:
            return session.agent_span_stack[-1]["span_id"]
        return session.root_span_id

    def _handle_session_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle SessionStart hook event."""
        session = self._get_or_create_session(session_id)
        model = body.get("model", "")
        if model:
            session.model = model
        log.info("Claude session started: %s (model=%s)", session_id, model)

    def _handle_user_prompt_submit(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle UserPromptSubmit hook event — starts a new trace for each user turn."""
        session = self._get_or_create_session(session_id)

        # If the previous turn's root span was emitted, start a fresh trace
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
            session.root_span_emitted = False

        prompt = body.get("user_prompt", body.get("prompt", ""))
        if prompt:
            session.user_prompts.append(prompt)

    def _handle_pre_tool_use(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle PreToolUse hook event — creates a pending tool span."""
        session = self._get_or_create_session(session_id)
        tool_name = body.get("tool_name", "unknown_tool")
        tool_input = body.get("tool_input", {})
        tool_use_id = body.get("tool_use_id", tool_name)
        session.tools_used.add(tool_name)

        span_id = _format_span_id()
        parent_id = self._current_parent_id(session)
        now_ns = int(time.time() * 1_000_000_000)

        session.pending_tools[tool_use_id] = PendingToolSpan(
            span_id=span_id,
            tool_name=tool_name,
            tool_input=tool_input,
            parent_id=parent_id,
            start_ns=now_ns,
        )

    def _handle_post_tool_use(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle PostToolUse hook event.

        If this is PostToolUse for a "Task" tool with a deferred agent span,
        emits the agent span (with Task I/O and span links) instead of a tool span.
        Otherwise emits a normal tool span.
        """
        session = self._get_or_create_session(session_id)
        tool_name = body.get("tool_name", "unknown_tool")
        tool_use_id = body.get("tool_use_id", tool_name)
        tool_output = body.get("tool_response", body.get("tool_output", ""))

        now_ns = int(time.time() * 1_000_000_000)

        pending = session.pending_tools.pop(tool_use_id, None)
        if pending:
            span_id = pending.span_id
            parent_id = pending.parent_id
            start_ns = pending.start_ns
            input_value = str(pending.tool_input) if pending.tool_input else ""
            actual_tool_name = pending.tool_name
        else:
            span_id = _format_span_id()
            parent_id = self._current_parent_id(session)
            start_ns = now_ns
            input_value = ""
            actual_tool_name = tool_name

        output_str = str(tool_output)[:4096] if tool_output else ""

        # Check if this Task tool has a deferred agent span to emit instead
        deferred = session.deferred_agent_spans.pop(tool_use_id, None)
        if deferred:
            # Emit the AGENT span with the Task tool's I/O and span links.
            # The agent span replaces the Task tool span in the linking chain.
            agent_span_id = deferred["span_id"]

            span_links = []
            if self._link_tracker:
                links = self._link_tracker.on_tool_call(
                    tool_use_id, agent_span_id, session.trace_id, deferred["parent_id"]
                )
                span_links = [link.to_dict() for link in links]

            span = {
                "span_id": agent_span_id,
                "trace_id": deferred["trace_id"],
                "parent_id": deferred["parent_id"],
                "name": deferred["name"],
                "status": "ok",
                "start_ns": deferred["start_ns"],
                "duration": deferred["duration"],
                "ml_app": "claude-code",
                "service": "claude-code",
                "env": "local",
                "tags": ["source:claude-code-hooks"],
                "meta": {
                    "span": {"kind": "agent"},
                    "input": {"value": input_value},
                    "output": {"value": output_str},
                },
                "metrics": {},
                "span_links": span_links,
            }
            self._assembled_spans.append(span)
            return

        # Normal tool span
        duration = now_ns - start_ns

        span_links = []
        if self._link_tracker:
            links = self._link_tracker.on_tool_call(tool_use_id, span_id, session.trace_id, parent_id)
            span_links = [link.to_dict() for link in links]

        span = {
            "span_id": span_id,
            "trace_id": session.trace_id,
            "parent_id": parent_id,
            "name": actual_tool_name,
            "status": "ok",
            "start_ns": start_ns,
            "duration": duration,
            "ml_app": "claude-code",
            "service": "claude-code",
            "env": "local",
            "tags": ["source:claude-code-hooks"],
            "meta": {
                "span": {"kind": "tool"},
                "input": {"value": input_value},
                "output": {"value": output_str},
            },
            "metrics": {},
            "span_links": span_links,
        }
        self._assembled_spans.append(span)

    def _handle_subagent_start(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle SubagentStart hook event — pushes a new agent onto the stack.

        If a pending "Task" tool exists, captures its tool_use_id and input so the
        agent span can absorb the Task tool's I/O and span links.
        """
        session = self._get_or_create_session(session_id)
        span_id = _format_span_id()
        parent_id = self._current_parent_id(session)
        now_ns = int(time.time() * 1_000_000_000)

        agent_name = body.get("agent_type", body.get("agent_name", "subagent"))

        # Find the pending "Task" tool that spawned this subagent.
        task_tool_use_id = ""
        task_tool_input: Any = None
        for tid, pending in session.pending_tools.items():
            if pending.tool_name == "Task":
                task_tool_use_id = tid
                task_tool_input = pending.tool_input
                break

        session.agent_span_stack.append(
            {
                "span_id": span_id,
                "parent_id": parent_id,
                "name": agent_name,
                "start_ns": now_ns,
                "task_tool_use_id": task_tool_use_id,
                "task_tool_input": task_tool_input,
            }
        )

    def _handle_subagent_stop(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle SubagentStop hook event — pops the agent stack.

        If the agent was spawned by a Task tool, defers span emission until
        PostToolUse(Task) fires so the agent span can include the Task's output.
        Otherwise emits the agent span immediately.
        """
        session = self._get_or_create_session(session_id)
        now_ns = int(time.time() * 1_000_000_000)

        if not session.agent_span_stack:
            log.warning("SubagentStop with empty agent stack for session %s", session_id)
            return

        agent_info = session.agent_span_stack.pop()
        duration = now_ns - agent_info["start_ns"]

        task_tool_use_id = agent_info.get("task_tool_use_id", "")
        task_tool_input = agent_info.get("task_tool_input")

        if task_tool_use_id:
            # Defer emission — PostToolUse(Task) will provide the output and emit
            session.deferred_agent_spans[task_tool_use_id] = {
                "span_id": agent_info["span_id"],
                "trace_id": session.trace_id,
                "parent_id": agent_info["parent_id"],
                "name": agent_info["name"],
                "start_ns": agent_info["start_ns"],
                "duration": duration,
                "input": str(task_tool_input) if task_tool_input else "",
            }
        else:
            span = {
                "span_id": agent_info["span_id"],
                "trace_id": session.trace_id,
                "parent_id": agent_info["parent_id"],
                "name": agent_info["name"],
                "status": "ok",
                "start_ns": agent_info["start_ns"],
                "duration": duration,
                "ml_app": "claude-code",
                "service": "claude-code",
                "env": "local",
                "tags": ["source:claude-code-hooks"],
                "meta": {
                    "span": {"kind": "agent"},
                    "input": {},
                    "output": {},
                },
                "metrics": {},
            }
            self._assembled_spans.append(span)

    def _handle_stop(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle Stop / SessionEnd hook event — finalizes the session root span."""
        session = self._sessions.get(session_id)
        if not session:
            log.warning("Stop event for unknown session %s", session_id)
            return

        now_ns = int(time.time() * 1_000_000_000)
        duration = now_ns - session.start_ns

        input_value = "\n\n".join(session.user_prompts) if session.user_prompts else ""
        transcript_path = body.get("transcript_path", "")
        output_value = _read_console_output(transcript_path)

        agent_manifest = {
            "name": "claude-code",
            "instructions": "",
            "handoff_description": "",
            "model": session.model,
            "model_provider": "anthropic",
            "model_settings": {},
            "tools": [{"name": name} for name in sorted(session.tools_used)],
            "handoffs": [],
            "guardrails": [],
        }

        span = {
            "span_id": session.root_span_id,
            "trace_id": session.trace_id,
            "parent_id": "undefined",
            "name": "claude-code-session",
            "status": "ok",
            "start_ns": session.start_ns,
            "duration": duration,
            "ml_app": "claude-code",
            "service": "claude-code",
            "env": "local",
            "tags": ["source:claude-code-hooks"],
            "meta": {
                "span": {"kind": "agent"},
                "input": {"value": input_value},
                "output": {"value": output_value},
                "model_name": session.model,
                "model_provider": "anthropic",
                "metadata": {
                    "agent_manifest": agent_manifest,
                    "model_name": session.model,
                    "model_provider": "anthropic",
                },
            },
            "metrics": {},
        }
        self._assembled_spans.append(span)
        session.root_span_emitted = True

    def _handle_notification(self, session_id: str, body: Dict[str, Any]) -> None:
        """Handle Notification hook event — logged but no span emitted."""
        log.info("Claude notification for session %s: %s", session_id, body.get("message", ""))

    def _dispatch_hook(self, body: Dict[str, Any]) -> None:
        """Dispatch a hook event to the appropriate handler."""
        session_id = body.get("session_id", "")
        hook_event_name = body.get("hook_event_name", "")

        handlers: Dict[str, Any] = {
            "SessionStart": self._handle_session_start,
            "UserPromptSubmit": self._handle_user_prompt_submit,
            "PreToolUse": self._handle_pre_tool_use,
            "PostToolUse": self._handle_post_tool_use,
            "SubagentStart": self._handle_subagent_start,
            "SubagentStop": self._handle_subagent_stop,
            "Stop": self._handle_stop,
            "SessionEnd": self._handle_stop,
            "Notification": self._handle_notification,
        }

        handler = handlers.get(hook_event_name)
        if handler:
            handler(session_id, body)
        else:
            log.debug("Unhandled hook event: %s", hook_event_name)

    async def _forward_trace_to_backend(self, session_id: str) -> None:
        """Forward all assembled spans for a session's trace to the backend via the EVP proxy path."""
        app = self._app
        if not app:
            return

        session = self._sessions.get(session_id)
        if not session:
            return

        trace_id = session.trace_id
        spans = [s for s in self._assembled_spans if s.get("trace_id") == trace_id]
        if not spans:
            return

        dd_site = app.get("dd_site", "")
        dd_api_key = app.get("dd_api_key")
        agent_url = app.get("agent_url", "")
        disable_forwarding = app.get("disable_llmobs_data_forwarding", False)

        if disable_forwarding:
            return

        if agent_url:
            url = f"{agent_url}/evp_proxy/v2/api/v2/llmobs"
            headers: Dict[str, str] = {"Content-Type": "application/msgpack", "Content-Encoding": "gzip"}
        elif dd_api_key and dd_site:
            url = f"https://llmobs-intake.{dd_site}/api/v2/llmobs"
            headers = {
                "Content-Type": "application/msgpack",
                "Content-Encoding": "gzip",
                "DD-API-KEY": dd_api_key,
            }
        else:
            log.debug("No DD_API_KEY/DD_SITE or agent URL configured — skipping LLMObs forwarding for Claude hooks")
            return

        payload = {
            "_dd.stage": "raw",
            "event_type": "span",
            "spans": spans,
        }
        data = gzip.compress(msgpack.packb(payload))

        try:
            async with ClientSession() as http_session:
                async with http_session.post(url, headers=headers, data=data) as resp:
                    if not resp.ok:
                        log.warning("Failed to forward Claude hooks spans: %s %s", resp.status, await resp.text())
                    else:
                        log.info("Forwarded %d Claude hooks spans for trace %s", len(spans), trace_id)
        except Exception as e:
            log.warning("Error forwarding Claude hooks spans: %s", e)

    async def handle_hook(self, request: Request) -> web.Response:
        """Handle POST /claude/hooks — receives hook JSON and dispatches by event name."""
        try:
            body = await request.json()
        except Exception:
            return web.json_response({"error": "invalid JSON"}, status=400)

        session_id = body.get("session_id", "")
        if not session_id:
            return web.json_response({"error": "missing session_id"}, status=400)

        self._raw_events.append(body)
        self._dispatch_hook(body)

        # Forward completed traces to the backend
        hook_event_name = body.get("hook_event_name", "")
        if hook_event_name in ("Stop", "SessionEnd"):
            await self._forward_trace_to_backend(session_id)

        return web.json_response({"status": "ok"})

    async def handle_sessions(self, request: Request) -> web.Response:
        """Handle GET /claude/hooks/sessions — list tracked sessions."""
        sessions = []
        for sid, state in self._sessions.items():
            sessions.append(
                {
                    "session_id": sid,
                    "trace_id": state.trace_id,
                    "root_span_id": state.root_span_id,
                    "num_prompts": len(state.user_prompts),
                    "agent_stack_depth": len(state.agent_span_stack),
                    "pending_tools": len(state.pending_tools),
                }
            )
        return web.json_response({"sessions": sessions})

    async def handle_spans(self, request: Request) -> web.Response:
        """Handle GET /claude/hooks/spans — return all assembled spans."""
        return web.json_response({"spans": self._assembled_spans})

    async def handle_raw_events(self, request: Request) -> web.Response:
        """Handle GET /claude/hooks/raw — return all raw received events for debugging."""
        return web.json_response({"events": self._raw_events})

    def get_routes(self) -> List[web.RouteDef]:
        """Return the routes for this API."""
        return [
            web.post("/claude/hooks", with_cors(self.handle_hook)),
            web.route("*", "/claude/hooks/sessions", with_cors(self.handle_sessions)),
            web.route("*", "/claude/hooks/spans", with_cors(self.handle_spans)),
            web.route("*", "/claude/hooks/raw", with_cors(self.handle_raw_events)),
        ]
