"""Anthropic API proxy for capturing LLM spans from Claude Code.

Acts as a transparent proxy between Claude Code and the Anthropic API,
creating LLM observability spans from the intercepted request/response data
and generating span links to connect them with tool/agent spans from hooks.

Usage:
    Set ANTHROPIC_BASE_URL=http://localhost:{port}/claude/proxy in Claude Code's
    environment to route all API calls through this proxy.
"""

import getpass
import json
import logging
import os
import socket
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

import aiohttp
from aiohttp import web
from aiohttp.web import Request

from .claude_hooks import ClaudeHooksAPI
from .claude_hooks import SessionState
from .claude_hooks import _format_span_id
from .claude_hooks import _format_trace_id
from .claude_link_tracker import ClaudeLinkTracker
from .claude_link_tracker import SpanLink
from .llmobs_event_platform import with_cors


log = logging.getLogger(__name__)

_HOSTNAME = socket.gethostname()
_USERNAME = os.environ.get("HOST_USER") or getpass.getuser()

ANTHROPIC_API_BASE = "https://api.anthropic.com"

SKIP_REQUEST_HEADERS = {"host", "transfer-encoding", "content-length"}
SKIP_RESPONSE_HEADERS = {"content-length", "transfer-encoding", "content-encoding", "connection"}

MODEL_CONTEXT_LIMITS: Dict[str, int] = {}  # empty; default fallback handles all models


def _get_context_limit(model: str) -> int:
    """Return the context window size for a given model."""
    if model in MODEL_CONTEXT_LIMITS:
        return MODEL_CONTEXT_LIMITS[model]
    return 200_000  # all current Claude models


def _compute_context_breakdown(total_input_tokens: int, model: str) -> Dict[str, Any]:
    context_window_size = _get_context_limit(model)
    context_usage_pct = round(total_input_tokens / context_window_size * 100, 1) if context_window_size > 0 else 0.0
    return {
        "context_window_size": context_window_size,
        "total_input_tokens": total_input_tokens,
        "context_usage_pct": context_usage_pct,
    }


def _parse_sse_events(raw: bytes) -> List[Dict[str, Any]]:
    """Parse raw SSE bytes into a list of {event, data} dicts."""
    events: List[Dict[str, Any]] = []
    text = raw.decode("utf-8", errors="replace")

    current_event = ""
    current_data_lines: List[str] = []

    for line in text.split("\n"):
        if line.startswith("event: "):
            current_event = line[7:].strip()
        elif line.startswith("data: "):
            current_data_lines.append(line[6:])
        elif line.strip() == "" and (current_event or current_data_lines):
            if current_data_lines:
                data_str = "\n".join(current_data_lines)
                try:
                    data = json.loads(data_str)
                    events.append({"event": current_event, "data": data})
                except json.JSONDecodeError:
                    pass
            current_event = ""
            current_data_lines = []

    return events


def _extract_response_from_sse(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Reconstruct a Messages API response from SSE events."""
    model = ""
    input_tokens = 0
    output_tokens = 0
    cache_read_input_tokens = 0
    cache_creation_input_tokens = 0
    stop_reason = ""
    content_blocks: List[Dict[str, Any]] = []
    block_builders: Dict[int, Dict[str, Any]] = {}

    for evt in events:
        event_type = evt.get("event", "")
        data = evt.get("data", {})

        if event_type == "message_start":
            msg = data.get("message", {})
            model = msg.get("model", "")
            usage = msg.get("usage", {})
            input_tokens = usage.get("input_tokens", 0)
            cache_read_input_tokens = usage.get("cache_read_input_tokens", 0)
            cache_creation_input_tokens = usage.get("cache_creation_input_tokens", 0)

        elif event_type == "content_block_start":
            index = data.get("index", 0)
            block = data.get("content_block", {})
            block_type = block.get("type", "")

            if block_type == "tool_use":
                block_builders[index] = {
                    "type": "tool_use",
                    "id": block.get("id", ""),
                    "name": block.get("name", ""),
                    "input_json_parts": [],
                }
            elif block_type == "text":
                block_builders[index] = {
                    "type": "text",
                    "text_parts": [],
                }
            elif block_type == "thinking":
                block_builders[index] = {
                    "type": "thinking",
                    "thinking_parts": [],
                }

        elif event_type == "content_block_delta":
            index = data.get("index", 0)
            delta = data.get("delta", {})
            delta_type = delta.get("type", "")
            builder = block_builders.get(index)
            if builder:
                if delta_type == "text_delta":
                    builder.setdefault("text_parts", []).append(delta.get("text", ""))
                elif delta_type == "input_json_delta":
                    builder.setdefault("input_json_parts", []).append(delta.get("partial_json", ""))
                elif delta_type == "thinking_delta":
                    builder.setdefault("thinking_parts", []).append(delta.get("thinking", ""))

        elif event_type == "content_block_stop":
            index = data.get("index", 0)
            builder = block_builders.pop(index, None)
            if builder:
                if builder["type"] == "text":
                    content_blocks.append(
                        {
                            "type": "text",
                            "text": "".join(builder.get("text_parts", [])),
                        }
                    )
                elif builder["type"] == "tool_use":
                    input_json_str = "".join(builder.get("input_json_parts", []))
                    try:
                        input_data = json.loads(input_json_str) if input_json_str else {}
                    except json.JSONDecodeError:
                        input_data = input_json_str
                    content_blocks.append(
                        {
                            "type": "tool_use",
                            "id": builder.get("id", ""),
                            "name": builder.get("name", ""),
                            "input": input_data,
                        }
                    )
                elif builder["type"] == "thinking":
                    content_blocks.append(
                        {
                            "type": "thinking",
                            "thinking": "".join(builder.get("thinking_parts", [])),
                        }
                    )

        elif event_type == "message_delta":
            delta = data.get("delta", {})
            stop_reason = delta.get("stop_reason", stop_reason)
            usage = data.get("usage", {})
            output_tokens = usage.get("output_tokens", output_tokens)

    return {
        "model": model,
        "content": content_blocks,
        "stop_reason": stop_reason,
        "usage": {
            "input_tokens": input_tokens,
            "cache_read_input_tokens": cache_read_input_tokens,
            "cache_creation_input_tokens": cache_creation_input_tokens,
            "output_tokens": output_tokens,
        },
    }


def _extract_tool_results_from_request(body: Dict[str, Any]) -> List[str]:
    """Extract tool_use_ids from tool_result blocks in the request messages."""
    tool_use_ids: List[str] = []
    for msg in body.get("messages", []):
        content = msg.get("content", [])
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_result":
                    tid = block.get("tool_use_id", "")
                    if tid:
                        tool_use_ids.append(tid)
    return tool_use_ids


def _extract_tool_uses_from_response(content_blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract tool_use blocks from the response content."""
    return [b for b in content_blocks if b.get("type") == "tool_use"]


def _format_input_messages(body: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Format request messages for the LLM span input."""
    messages: List[Dict[str, Any]] = []
    for msg in body.get("messages", []):
        role = msg.get("role", "")
        content = msg.get("content", "")
        if isinstance(content, str):
            messages.append({"role": role, "content": content})
        elif isinstance(content, list):
            parts: List[str] = []
            for block in content:
                if isinstance(block, dict):
                    btype = block.get("type", "")
                    if btype == "text":
                        parts.append(block.get("text", ""))
                    elif btype == "tool_result":
                        parts.append(f"[tool_result:{block.get('tool_use_id', '')}]")
                    elif btype == "tool_use":
                        parts.append(f"[tool_use:{block.get('name', '')}]")
                    else:
                        parts.append(f"[{btype}]")
            messages.append({"role": role, "content": " ".join(parts)})
    return messages


def _format_output_messages(content_blocks: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Format response content blocks for the LLM span output."""
    messages: List[Dict[str, Any]] = []
    for block in content_blocks:
        btype = block.get("type", "")
        if btype == "text":
            messages.append({"role": "assistant", "content": block.get("text", "")})
        elif btype == "tool_use":
            messages.append(
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "name": block.get("name", ""),
                            "arguments": block.get("input", {}),
                            "tool_id": block.get("id", ""),
                            "type": "tool_use",
                        }
                    ],
                }
            )
    return messages


class ClaudeProxyAPI:
    """Transparent proxy for Anthropic API calls that creates LLM spans."""

    def __init__(self, hooks_api: ClaudeHooksAPI, link_tracker: ClaudeLinkTracker) -> None:
        self._hooks_api = hooks_api
        self._link_tracker = link_tracker
        self._http_session: Optional[aiohttp.ClientSession] = None
        # Spans created before any session existed; re-parented when a session appears.
        self._orphan_spans: List[Dict[str, Any]] = []

    async def _get_http_session(self) -> aiohttp.ClientSession:
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession()
        return self._http_session

    async def close(self) -> None:
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()

    def _get_active_session(self) -> Optional[SessionState]:
        """Get the most likely active Claude session.

        Prefers sessions that have pending tools or an active agent stack
        (indicating they are mid-turn), then falls back to sessions that
        haven't emitted their root span yet (not yet completed).  This
        prevents LLM spans from being assigned to a finished/test session
        when multiple sessions exist.
        """
        sessions = self._hooks_api._sessions
        if not sessions:
            return None

        all_sessions = list(sessions.values())

        # Prefer sessions with pending tools (actively executing)
        for s in reversed(all_sessions):
            if s.pending_tools or s.agent_span_stack:
                return s

        # Then prefer sessions that haven't finished their turn yet
        for s in reversed(all_sessions):
            if not s.root_span_emitted:
                return s

        # Fallback to the most recently created session
        return all_sessions[-1]

    def _adopt_orphan_spans(self, session: SessionState) -> None:
        """Re-parent buffered orphan spans into the given session's trace."""
        if not self._orphan_spans:
            return
        for span in self._orphan_spans:
            span["trace_id"] = session.trace_id
            span["parent_id"] = session.root_span_id
        log.info("Re-parented %d orphan LLM spans into trace %s", len(self._orphan_spans), session.trace_id)
        self._orphan_spans.clear()

    @staticmethod
    def _extract_conversation_title(session: SessionState, content_blocks: List[Dict[str, Any]]) -> None:
        """Detect the haiku summarization response and store the title on the session."""
        for block in content_blocks:
            if block.get("type") != "text":
                continue
            text = block.get("text", "").strip()
            if not text.startswith("{"):
                continue
            try:
                data = json.loads(text)
            except (json.JSONDecodeError, ValueError):
                continue
            if "title" in data and "isNewTopic" in data:
                title = data["title"]
                if isinstance(title, str) and title:
                    session.conversation_title = title
                    log.info("Conversation title: %s", title)
                return

    def _create_llm_span(
        self,
        session: Optional[SessionState],
        request_body: Dict[str, Any],
        response_data: Dict[str, Any],
        start_ns: int,
        duration_ns: int,
    ) -> Dict[str, Any]:
        """Create an LLM span from the proxy request/response data."""
        model = response_data.get("model", request_body.get("model", "unknown"))
        usage = response_data.get("usage", {})
        content_blocks = response_data.get("content", [])

        # Anthropic prompt caching: input_tokens only counts non-cached tokens.
        # Total input = input_tokens + cache_read + cache_creation.
        raw_input_tokens = usage.get("input_tokens", 0)
        cache_read = usage.get("cache_read_input_tokens", 0)
        cache_creation = usage.get("cache_creation_input_tokens", 0)
        total_input_tokens = raw_input_tokens + cache_read + cache_creation

        # Re-resolve session if we didn't have one at request time
        # (hooks may have fired while the upstream call was in flight)
        if not session:
            session = self._get_active_session()

        if session:
            trace_id = session.trace_id
            # Default parent: use the agent stack (works for sequential execution)
            parent_id = self._hooks_api._current_parent_id(session)
            # Adopt any previously orphaned spans now that we have a session
            self._adopt_orphan_spans(session)
        else:
            trace_id = _format_trace_id()
            parent_id = "undefined"

        span_id = _format_span_id()

        # Tool.output -> LLM.input linking: check for tool_result in the request.
        # Also collects parent_id hints from the tool spans — this is how we resolve
        # the correct parent when concurrent subagents are active.
        tool_result_ids = _extract_tool_results_from_request(request_body)
        span_links: List[SpanLink] = []
        parent_hints: List[str] = []
        for tool_use_id in tool_result_ids:
            links, parent_hint = self._link_tracker.on_tool_call_output_used(tool_use_id)
            span_links.extend(links)
            if parent_hint:
                parent_hints.append(parent_hint)

        # If tool_result correlation gives us a consistent parent, prefer it over the
        # stack-based heuristic (which breaks with concurrent subagents).
        if parent_hints:
            # All tool_results in a single LLM request should come from the same parent.
            # Use the first hint; if they disagree, still better than the stack guess.
            parent_id = parent_hints[0]

        # LLM.output -> Tool.input linking: register tool_use blocks from the response
        tool_uses = _extract_tool_uses_from_response(content_blocks)
        for tu in tool_uses:
            self._link_tracker.on_llm_tool_choice(
                tool_use_id=tu.get("id", ""),
                tool_name=tu.get("name", ""),
                arguments=json.dumps(tu.get("input", {}), sort_keys=True),
                llm_span_id=span_id,
                llm_trace_id=trace_id,
            )

        input_messages = _format_input_messages(request_body)
        output_messages = _format_output_messages(content_blocks)

        # Detect haiku summarization call and extract conversation title
        if session:
            self._extract_conversation_title(session, content_blocks)

        # Compute context breakdown for the UI
        context_breakdown = _compute_context_breakdown(total_input_tokens, model)

        # Attach session_id so LLM spans can be grouped with the session
        session_id = session.session_id if session else ""

        span: Dict[str, Any] = {
            "span_id": span_id,
            "trace_id": trace_id,
            "parent_id": parent_id,
            "name": model,
            "status": "ok",
            "start_ns": start_ns,
            "duration": duration_ns,
            "ml_app": "claude-code",
            "service": "claude-code",
            "env": "local",
            "session_id": session_id,
            "tags": [
                "ml_app:claude-code",
                "service:claude-code",
                "env:local",
                "source:claude-code-proxy",
                "language:python",
                f"hostname:{_HOSTNAME}",
                f"user_name:{_USERNAME}",
            ]
            + ([f"session_id:{session_id}"] if session_id else []),
            "meta": {
                "span": {"kind": "llm"},
                "model_name": model,
                "model_provider": "anthropic",
                "input": {"messages": input_messages},
                "output": {"messages": output_messages},
                "metadata": {
                    "stop_reason": response_data.get("stop_reason", ""),
                    "stream": request_body.get("stream", False),
                    "context_breakdown": context_breakdown,
                },
            },
            "metrics": {
                "input_tokens": total_input_tokens,
                "output_tokens": usage.get("output_tokens", 0),
                "total_tokens": total_input_tokens + usage.get("output_tokens", 0),
                "cache_read_input_tokens": cache_read,
                "cache_write_input_tokens": cache_creation,
                "non_cached_input_tokens": raw_input_tokens,
            },
            "span_links": [link.to_dict() for link in span_links],
        }
        return span

    async def handle_proxy(self, request: Request) -> web.StreamResponse:
        """Proxy an Anthropic API request, creating an LLM span."""
        path = request.match_info.get("path", "")
        target_url = f"{ANTHROPIC_API_BASE}/{path}"
        if request.query_string:
            target_url += f"?{request.query_string}"

        body_bytes = await request.read()

        request_body: Dict[str, Any] = {}
        try:
            if body_bytes:
                request_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            pass

        is_streaming = request_body.get("stream", False)

        headers = {key: value for key, value in request.headers.items() if key.lower() not in SKIP_REQUEST_HEADERS}

        start_ns = int(time.time() * 1_000_000_000)
        session = self._get_active_session()

        http_session = await self._get_http_session()

        try:
            async with http_session.request(
                request.method,
                target_url,
                headers=headers,
                data=body_bytes,
            ) as upstream_resp:
                if is_streaming:
                    return await self._handle_streaming(request, upstream_resp, request_body, session, start_ns)
                else:
                    return await self._handle_non_streaming(upstream_resp, request_body, session, start_ns)
        except Exception as e:
            log.error("Proxy error forwarding to %s: %s", target_url, e)
            return web.json_response(
                {"error": {"type": "proxy_error", "message": str(e)}},
                status=502,
            )

    async def _handle_streaming(
        self,
        request: Request,
        upstream_resp: aiohttp.ClientResponse,
        request_body: Dict[str, Any],
        session: Optional[SessionState],
        start_ns: int,
    ) -> web.StreamResponse:
        """Tee a streaming SSE response and create an LLM span after completion."""
        response = web.StreamResponse(status=upstream_resp.status)
        for key, value in upstream_resp.headers.items():
            if key.lower() not in SKIP_RESPONSE_HEADERS:
                response.headers[key] = value
        await response.prepare(request)

        buffered_chunks: List[bytes] = []
        async for chunk in upstream_resp.content.iter_any():
            await response.write(chunk)
            buffered_chunks.append(chunk)
        await response.write_eof()

        end_ns = int(time.time() * 1_000_000_000)
        duration_ns = end_ns - start_ns

        if upstream_resp.status == 200:
            try:
                raw = b"".join(buffered_chunks)
                sse_events = _parse_sse_events(raw)
                response_data = _extract_response_from_sse(sse_events)

                span = self._create_llm_span(session, request_body, response_data, start_ns, duration_ns)
                if span.get("parent_id") == "undefined":
                    # No session yet — buffer for later re-parenting
                    self._orphan_spans.append(span)
                    self._hooks_api._assembled_spans.append(span)
                    log.info("Buffered orphan LLM span %s (no session yet)", span["span_id"])
                else:
                    self._hooks_api._assembled_spans.append(span)
                log.info(
                    "LLM span %s: model=%s tokens=%d+%d duration=%.1fs",
                    span["span_id"],
                    response_data.get("model", "?"),
                    span["metrics"].get("input_tokens", 0),
                    span["metrics"].get("output_tokens", 0),
                    duration_ns / 1_000_000_000,
                )
            except Exception as e:
                log.error("Failed to create LLM span from SSE: %s", e, exc_info=True)

        return response

    async def _handle_non_streaming(
        self,
        upstream_resp: aiohttp.ClientResponse,
        request_body: Dict[str, Any],
        session: Optional[SessionState],
        start_ns: int,
    ) -> web.Response:
        """Handle a non-streaming JSON response."""
        body = await upstream_resp.read()
        end_ns = int(time.time() * 1_000_000_000)
        duration_ns = end_ns - start_ns

        if upstream_resp.status == 200:
            try:
                response_data = json.loads(body)
                span = self._create_llm_span(session, request_body, response_data, start_ns, duration_ns)
                if span.get("parent_id") == "undefined":
                    self._orphan_spans.append(span)
                    self._hooks_api._assembled_spans.append(span)
                    log.info("Buffered orphan LLM span %s (no session yet)", span["span_id"])
                else:
                    self._hooks_api._assembled_spans.append(span)
                log.info(
                    "LLM span %s: model=%s tokens=%d+%d duration=%.1fs",
                    span["span_id"],
                    response_data.get("model", "?"),
                    span["metrics"].get("input_tokens", 0),
                    span["metrics"].get("output_tokens", 0),
                    duration_ns / 1_000_000_000,
                )
            except Exception as e:
                log.error("Failed to create LLM span: %s", e, exc_info=True)

        resp = web.Response(body=body, status=upstream_resp.status)
        for key, value in upstream_resp.headers.items():
            if key.lower() not in SKIP_RESPONSE_HEADERS:
                resp.headers[key] = value
        return resp

    def get_routes(self) -> List[web.RouteDef]:
        return [
            web.route("*", "/claude/proxy/{path:.*}", with_cors(self.handle_proxy)),
        ]
