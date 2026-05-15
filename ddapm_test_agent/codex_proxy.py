"""OpenAI-compatible proxy for capturing Codex LLM spans."""

import json
import logging
import os
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from urllib.parse import urlparse

import aiohttp
from aiohttp import web
from aiohttp.web import Request

from ._clock import monotonic_wall_ns
from .claude_hooks import _format_span_id
from .claude_hooks import _format_trace_id
from .codex_cost_tracker import compute_openai_cost_metrics
from .codex_hooks import CodexHooksAPI
from .llmobs_event_platform import with_cors

log = logging.getLogger(__name__)

OPENAI_API_BASE = os.environ.get("DD_CODEX_OPENAI_API_BASE", "https://api.openai.com")
ALLOW_UPSTREAM_OVERRIDE_ENV = "DD_CODEX_ALLOW_UPSTREAM_OVERRIDE"
SKIP_REQUEST_HEADERS = {"host", "transfer-encoding", "content-length", "x-ddapm-upstream"}
SKIP_RESPONSE_HEADERS = {"content-length", "transfer-encoding", "content-encoding", "connection"}


def _is_client_disconnect_error(exc: BaseException) -> bool:
    if isinstance(exc, (aiohttp.ClientConnectionResetError, ConnectionResetError, BrokenPipeError)):
        return True
    return isinstance(exc, RuntimeError) and "closing transport" in str(exc)


def _allow_upstream_override() -> bool:
    return os.environ.get(ALLOW_UPSTREAM_OVERRIDE_ENV, "").lower() in ("1", "true", "yes")


def _upstream_origin_from_request(request: Request) -> str:
    upstream_override = request.headers.get("X-DDAPM-Upstream")
    if not upstream_override:
        return OPENAI_API_BASE.rstrip("/")
    if not _allow_upstream_override():
        raise web.HTTPForbidden(text="X-DDAPM-Upstream override is disabled")

    upstream_origin = upstream_override.rstrip("/")
    parsed = urlparse(upstream_origin)
    if parsed.scheme not in ("http", "https") or not parsed.netloc or parsed.path not in ("", "/"):
        raise web.HTTPBadRequest(text="invalid X-DDAPM-Upstream origin")
    return upstream_origin


def _parse_sse_events(raw: bytes) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    text = raw.decode("utf-8", errors="replace")
    current_event = ""
    current_data_lines: List[str] = []

    for line in text.split("\n"):
        if line.startswith("event: "):
            current_event = line[7:].strip()
        elif line.startswith("data: "):
            data_line = line[6:].strip()
            if data_line == "[DONE]":
                continue
            current_data_lines.append(data_line)
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


def _response_from_sse(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    text_parts: List[str] = []
    model = ""
    usage: Dict[str, Any] = {}

    for event in events:
        data = event.get("data", {})
        event_name = event.get("event", "")
        event_type = data.get("type", event_name)
        response = data.get("response")
        if isinstance(response, dict):
            model = response.get("model", model)
            usage = response.get("usage", usage) or usage
            if event_type in ("response.completed", "response.incomplete"):
                return response
        if event_type == "response.output_text.delta":
            delta = data.get("delta", "")
            if delta:
                text_parts.append(str(delta))
        elif event_type == "response.output_text.done":
            text = data.get("text", "")
            if text:
                text_parts = [str(text)]

    return {
        "model": model,
        "output": [
            {
                "type": "message",
                "role": "assistant",
                "content": [{"type": "output_text", "text": "".join(text_parts)}],
            }
        ],
        "usage": usage,
    }


def _content_to_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts: List[str] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type", "")
        if item_type in ("input_text", "output_text", "text"):
            text = item.get("text", "")
            if text:
                parts.append(str(text))
        elif item_type in ("input_image", "image_url"):
            parts.append("[image]")
        elif item_type in ("function_call_output", "tool_result"):
            parts.append(str(item.get("output", item.get("content", ""))))
    return "\n".join(parts)


def _format_input_messages(body: Dict[str, Any]) -> List[Dict[str, Any]]:
    input_value = body.get("input", [])
    if isinstance(input_value, str):
        return [{"role": "user", "content": input_value}]
    if not isinstance(input_value, list):
        return []

    messages: List[Dict[str, Any]] = []
    for item in input_value:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type", "")
        if item_type in ("message", "input_message") or "role" in item:
            messages.append(
                {
                    "role": item.get("role", "user"),
                    "content": _content_to_text(item.get("content", "")),
                }
            )
        elif item_type == "function_call_output":
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": item.get("call_id", ""),
                    "content": _content_to_text(item.get("output", "")),
                }
            )
    return messages


def _format_output_messages(response: Dict[str, Any]) -> List[Dict[str, Any]]:
    output = response.get("output", [])
    if not isinstance(output, list):
        return []

    messages: List[Dict[str, Any]] = []
    for item in output:
        if not isinstance(item, dict):
            continue
        item_type = item.get("type", "")
        if item_type == "message":
            messages.append(
                {
                    "role": item.get("role", "assistant"),
                    "content": _content_to_text(item.get("content", "")),
                }
            )
        elif item_type == "function_call":
            arguments = item.get("arguments", "")
            try:
                parsed_arguments = json.loads(arguments) if isinstance(arguments, str) else arguments
            except (TypeError, ValueError):
                parsed_arguments = arguments
            messages.append(
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": item.get("call_id", item.get("id", "")),
                            "name": item.get("name", ""),
                            "arguments": parsed_arguments,
                        }
                    ],
                }
            )
    return messages


def _has_output_messages(messages: List[Dict[str, Any]]) -> bool:
    return any(message.get("content") or message.get("tool_calls") for message in messages)


def _usage_metrics(model: str, usage: Dict[str, Any]) -> Dict[str, Any]:
    input_tokens = int(usage.get("input_tokens", usage.get("prompt_tokens", 0)) or 0)
    output_tokens = int(usage.get("output_tokens", usage.get("completion_tokens", 0)) or 0)
    total_tokens = int(usage.get("total_tokens", input_tokens + output_tokens) or 0)
    input_details = usage.get("input_tokens_details", {}) or usage.get("prompt_tokens_details", {}) or {}
    output_details = usage.get("output_tokens_details", {}) or usage.get("completion_tokens_details", {}) or {}
    cached_input_tokens = int(input_details.get("cached_tokens", usage.get("cached_input_tokens", 0)) or 0)
    reasoning_output_tokens = int(output_details.get("reasoning_tokens", usage.get("reasoning_output_tokens", 0)) or 0)
    non_cached_input_tokens = max(input_tokens - cached_input_tokens, 0)

    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
        "cache_read_input_tokens": cached_input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "cache_write_input_tokens": 0,
        "non_cached_input_tokens": non_cached_input_tokens,
        "reasoning_output_tokens": reasoning_output_tokens,
        **compute_openai_cost_metrics(
            model_id=model,
            non_cached_input_tokens=non_cached_input_tokens,
            cached_input_tokens=cached_input_tokens,
            output_tokens=output_tokens,
        ),
    }


class CodexProxyAPI:
    """Transparent OpenAI API proxy that creates Codex LLM spans."""

    def __init__(self, hooks_api: CodexHooksAPI) -> None:
        self._hooks_api = hooks_api
        self._http_session: Optional[aiohttp.ClientSession] = None

    async def _get_http_session(self) -> aiohttp.ClientSession:
        if self._http_session is None or self._http_session.closed:
            self._http_session = aiohttp.ClientSession()
        return self._http_session

    async def close(self) -> None:
        if self._http_session and not self._http_session.closed:
            await self._http_session.close()

    def _create_llm_span(
        self,
        request_body: Dict[str, Any],
        response_data: Dict[str, Any],
        start_ns: int,
        duration_ns: int,
    ) -> Optional[Dict[str, Any]]:
        model = response_data.get("model") or request_body.get("model") or "unknown"
        output_messages = _format_output_messages(response_data)
        if not _has_output_messages(output_messages):
            return None
        usage = response_data.get("usage", {}) or {}
        return {
            "span_id": _format_span_id(),
            "trace_id": _format_trace_id(),
            "parent_id": "undefined",
            "name": model,
            "status": "ok",
            "start_ns": start_ns,
            "duration": duration_ns,
            "ml_app": self._hooks_api._config.ml_app,
            "service": self._hooks_api._config.service,
            "env": self._hooks_api._config.env,
            "session_id": "",
            "tags": [
                f"ml_app:{self._hooks_api._config.ml_app}",
                f"service:{self._hooks_api._config.service}",
                f"env:{self._hooks_api._config.env}",
                "source:codex-proxy",
                "language:python",
                f"hostname:{self._hooks_api._config.hostname}",
            ],
            "meta": {
                "span": {"kind": "llm"},
                "model_name": model,
                "model_provider": "openai",
                "input": {"messages": _format_input_messages(request_body)},
                "output": {"messages": output_messages},
                "metadata": {
                    "stream": request_body.get("stream", False),
                    "response_id": response_data.get("id", ""),
                    "status": response_data.get("status", ""),
                },
            },
            "metrics": _usage_metrics(model, usage),
        }

    async def handle_proxy(self, request: Request) -> web.StreamResponse:
        path = request.match_info.get("path", "")
        proxy_session_key = request.match_info.get("proxy_session_key", "") or None
        upstream_origin = _upstream_origin_from_request(request)
        target_url = f"{upstream_origin}/v1/{path}"
        if request.query_string:
            target_url += f"?{request.query_string}"

        body_bytes = await request.read()
        request_body: Dict[str, Any] = {}
        try:
            if body_bytes:
                request_body = json.loads(body_bytes)
        except json.JSONDecodeError:
            pass

        start_ns = monotonic_wall_ns()
        maybe_session_id = self._hooks_api.begin_proxy_llm_call(proxy_session_key, start_ns)
        headers = {key: value for key, value in request.headers.items() if key.lower() not in SKIP_REQUEST_HEADERS}
        http_session = await self._get_http_session()

        try:
            async with http_session.request(
                request.method,
                target_url,
                headers=headers,
                data=body_bytes,
            ) as upstream_resp:
                if request_body.get("stream", False):
                    return await self._handle_streaming(
                        request, upstream_resp, request_body, maybe_session_id, start_ns
                    )
                return await self._handle_non_streaming(upstream_resp, request_body, maybe_session_id, start_ns)
        except Exception as exc:
            self._hooks_api.finish_proxy_llm_call(maybe_session_id, succeeded=False)
            if _is_client_disconnect_error(exc):
                log.debug("Codex proxy client disconnected while forwarding to %s: %s", target_url, exc)
                return web.Response(status=499)
            log.error("Codex proxy error forwarding to %s: %s", target_url, exc)
            return web.json_response({"error": {"type": "proxy_error", "message": str(exc)}}, status=502)

    async def _handle_streaming(
        self,
        request: Request,
        upstream_resp: aiohttp.ClientResponse,
        request_body: Dict[str, Any],
        maybe_session_id: Optional[str],
        start_ns: int,
    ) -> web.StreamResponse:
        response = web.StreamResponse(status=upstream_resp.status)
        for key, value in upstream_resp.headers.items():
            if key.lower() not in SKIP_RESPONSE_HEADERS:
                response.headers[key] = value
        await response.prepare(request)

        buffered_chunks: List[bytes] = []
        downstream_closed = False
        async for chunk in upstream_resp.content.iter_any():
            try:
                await response.write(chunk)
            except Exception as exc:
                if not _is_client_disconnect_error(exc):
                    raise
                downstream_closed = True
                upstream_resp.close()
                log.debug("Codex proxy client disconnected while streaming response: %s", exc)
                break
            buffered_chunks.append(chunk)
        if downstream_closed:
            self._hooks_api.finish_proxy_llm_call(maybe_session_id, succeeded=False)
            return response
        if not downstream_closed:
            try:
                await response.write_eof()
            except Exception as exc:
                if not _is_client_disconnect_error(exc):
                    raise
                log.debug("Codex proxy client disconnected before stream EOF: %s", exc)

        if upstream_resp.status == 200:
            end_ns = monotonic_wall_ns()
            raw = b"".join(buffered_chunks)
            try:
                response_data = _response_from_sse(_parse_sse_events(raw))
                span = self._create_llm_span(request_body, response_data, start_ns, end_ns - start_ns)
                if span is not None:
                    self._hooks_api.register_proxy_llm_span(maybe_session_id, span, start_ns, end_ns)
                else:
                    self._hooks_api.finish_proxy_llm_call(maybe_session_id, succeeded=False)
            except Exception as exc:
                self._hooks_api.finish_proxy_llm_call(maybe_session_id, succeeded=False)
                log.error("Failed to create Codex LLM span from SSE: %s", exc, exc_info=True)
        else:
            self._hooks_api.finish_proxy_llm_call(maybe_session_id, succeeded=False)

        return response

    async def _handle_non_streaming(
        self,
        upstream_resp: aiohttp.ClientResponse,
        request_body: Dict[str, Any],
        maybe_session_id: Optional[str],
        start_ns: int,
    ) -> web.Response:
        body = await upstream_resp.read()
        if upstream_resp.status == 200:
            end_ns = monotonic_wall_ns()
            try:
                response_data = json.loads(body)
                span = self._create_llm_span(request_body, response_data, start_ns, end_ns - start_ns)
                if span is not None:
                    self._hooks_api.register_proxy_llm_span(maybe_session_id, span, start_ns, end_ns)
                else:
                    self._hooks_api.finish_proxy_llm_call(maybe_session_id, succeeded=False)
            except Exception as exc:
                self._hooks_api.finish_proxy_llm_call(maybe_session_id, succeeded=False)
                log.error("Failed to create Codex LLM span: %s", exc, exc_info=True)
        else:
            self._hooks_api.finish_proxy_llm_call(maybe_session_id, succeeded=False)

        response = web.Response(body=body, status=upstream_resp.status)
        for key, value in upstream_resp.headers.items():
            if key.lower() not in SKIP_RESPONSE_HEADERS:
                response.headers[key] = value
        return response

    def get_routes(self) -> List[web.RouteDef]:
        return [
            web.route("*", "/codex/proxy/{proxy_session_key}/v1/{path:.*}", with_cors(self.handle_proxy)),
            web.route("*", "/codex/proxy/v1/{path:.*}", with_cors(self.handle_proxy)),
        ]
