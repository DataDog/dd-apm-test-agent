import asyncio
import datetime
import json
import logging
from pathlib import Path
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Protocol
from typing import Tuple
import urllib.parse
import weakref

from aiohttp import web
from aiohttp.web import StreamResponse
from jinja2 import Environment
from jinja2 import FileSystemLoader


log = logging.getLogger(__name__)


class BodyProcessor:
    """Utility class for processing request/response bodies"""

    @staticmethod
    def process_body(body_data: bytes, content_type: str) -> Tuple[str, bool]:
        """
        Process body data for display
        Returns: (processed_body, is_binary)
        """
        if not body_data:
            return "", False

        content_type = content_type or ""

        # Check if this is binary content that should be base64 encoded
        if (
            "msgpack" in content_type.lower()
            or "application/octet-stream" in content_type.lower()
            or "multipart" in content_type.lower()
        ):
            import base64

            return base64.b64encode(body_data).decode("ascii"), True
        else:
            # Try to decode as text
            try:
                return body_data.decode("utf-8", errors="replace"), False
            except Exception:
                return "[Binary data]", False


class TraceProcessor:
    """Utility class for processing trace data"""

    @staticmethod
    def process_traces(raw_data: bytes, content_type: str, path: str, suppress_errors: bool = False) -> Dict:
        """Process trace data and return standardized trace information"""
        if not raw_data:
            return TraceProcessor._empty_trace_result(path)

        try:
            # Import decode functions
            from .trace import decode_v1 as trace_decode_v1
            from .trace import decode_v04 as trace_decode_v04
            from .trace import decode_v05 as trace_decode_v05
            from .trace import decode_v07 as trace_decode_v07

            # Decode based on path
            traces = []
            log.info(f"Decoding trace data for path: {path}, data length: {len(raw_data)}")
            if path == "/v0.4/traces":
                traces = trace_decode_v04(content_type, raw_data, suppress_errors)
            elif path == "/v0.5/traces":
                traces = trace_decode_v05(raw_data)
            elif path == "/v0.7/traces":
                traces = trace_decode_v07(raw_data)
            elif path == "/v1.0/traces":
                traces = trace_decode_v1(raw_data)
            log.info(f"Decoded {len(traces)} traces for {path}")

            return TraceProcessor._process_decoded_traces(traces, path)

        except Exception as e:
            log.error(f"Failed to process trace data: {e}")
            return TraceProcessor._empty_trace_result(path)

    @staticmethod
    def _process_decoded_traces(traces: List, path: str) -> Dict:
        """Convert decoded traces to standardized format"""
        # Count traces and spans
        trace_count = len(traces)
        span_count = sum(len(trace) for trace in traces)

        # Convert spans to dict format for JSON serialization
        trace_data = []
        for trace in traces:
            trace_spans = []
            for span in trace:
                # Handle both dict and object formats
                if hasattr(span, "trace_id"):
                    # Span object with attributes
                    span_dict = {
                        "trace_id": span.trace_id,
                        "span_id": span.span_id,
                        "parent_id": span.parent_id,
                        "service": span.service,
                        "name": span.name,
                        "resource": span.resource,
                        "type": span.type,
                        "start": span.start,
                        "duration": span.duration,
                        "error": span.error,
                        "meta": span.meta,
                        "metrics": span.metrics,
                    }
                else:
                    # Already a dictionary
                    span_dict = {
                        "trace_id": span.get("trace_id"),
                        "span_id": span.get("span_id"),
                        "parent_id": span.get("parent_id"),
                        "service": span.get("service"),
                        "name": span.get("name"),
                        "resource": span.get("resource"),
                        "type": span.get("type"),
                        "start": span.get("start"),
                        "duration": span.get("duration"),
                        "error": span.get("error"),
                        "meta": span.get("meta", {}),
                        "metrics": span.get("metrics", {}),
                    }
                trace_spans.append(span_dict)
            trace_data.append(trace_spans)

        # Encode trace data as base64 JSON for JavaScript
        import base64
        import json

        trace_json = json.dumps(trace_data)
        trace_data_b64 = base64.b64encode(trace_json.encode("utf-8")).decode("ascii")

        return {
            "is_trace_request": True,
            "path": path,
            "trace_count": trace_count,
            "span_count": span_count,
            "traces": trace_data,
            "trace_data_b64": trace_data_b64,
        }

    @staticmethod
    def _empty_trace_result(path: str) -> Dict:
        """Return empty trace result for error cases"""
        return {
            "is_trace_request": True,
            "path": path,
            "trace_count": 0,
            "span_count": 0,
            "traces": [],
            "trace_data_b64": "",
        }


class RequestObserver(Protocol):
    """Observer interface for request notifications"""

    async def notify_request(self, request_data: Dict) -> None: ...


class RequestStorage:
    """Centralized storage for all request/response data"""

    def __init__(self, max_requests: int = 200):
        self._requests: List[Dict] = []
        self._max_requests = max_requests
        self._observers: List[RequestObserver] = []

    def add_request(self, request_data: Dict) -> None:
        """Add a new request and notify observers"""
        self._requests.append(request_data)

        # Maintain size limit
        if len(self._requests) > self._max_requests:
            self._requests.pop(0)

        # Notify observers asynchronously
        import asyncio

        for observer in self._observers:
            try:
                asyncio.create_task(observer.notify_request(request_data))
            except Exception:
                # Don't let observer failures break request processing
                pass

    def get_all_requests(self) -> List[Dict]:
        """Get all stored requests (most recent first)"""
        return list(reversed(self._requests))

    def clear_requests(self) -> None:
        """Clear all stored requests"""
        self._requests.clear()

    def add_observer(self, observer: RequestObserver) -> None:
        """Add an observer for request notifications"""
        self._observers.append(observer)

    def remove_observer(self, observer: RequestObserver) -> None:
        """Remove an observer"""
        if observer in self._observers:
            self._observers.remove(observer)

    def __len__(self) -> int:
        return len(self._requests)


# Global request storage instance (initialized with default, can be reconfigured)
request_storage = None


@web.middleware
async def request_response_capture_middleware(request: web.Request, handler):
    """Middleware to capture all request/response data for WebUI"""
    request_start_time = time.time()

    # Capture request data
    request_body = b""
    if request.has_body and request.can_read_body:
        try:
            request_body = await request.read()
            # Store the body back on the request for handlers to use
            request._payload = request_body
        except Exception as e:
            log.debug(f"Failed to read request body: {e}")

    # Process the request
    response_status = 500
    response_headers = {}
    response_body = b""

    try:
        response = await handler(request)
        response_status = response.status
        response_headers = dict(response.headers)

        # Capture response body if it's a regular response
        if hasattr(response, "body") and response.body:
            response_body = response.body
        elif hasattr(response, "text") and response.text:
            response_body = response.text.encode("utf-8")

    except Exception as e:
        # Handle errors
        response_status = 500
        response_headers = {}
        response_body = str(e).encode("utf-8")
        # Store data even on error, then re-raise
        request_data = {
            "timestamp": request_start_time,
            "method": request.method,
            "path": request.path_qs,
            "headers": dict(request.headers),
            "content_type": request.headers.get("Content-Type", ""),
            "remote_addr": request.remote or "",
            "request_body": request_body,
            "response": {
                "status": response_status,
                "headers": response_headers,
                "body": response_body,
            },
            "duration_ms": (time.time() - request_start_time) * 1000,
        }
        request_storage.add_request(request_data)
        raise

    # Store captured data for successful requests
    request_data = {
        "timestamp": request_start_time,
        "method": request.method,
        "path": request.path_qs,
        "headers": dict(request.headers),
        "content_type": request.headers.get("Content-Type", ""),
        "remote_addr": request.remote or "",
        "request_body": request_body,
        "response": {
            "status": response_status,
            "headers": response_headers,
            "body": response_body,
        },
        "duration_ms": (time.time() - request_start_time) * 1000,
    }

    # Store in unified request storage (with automatic size limit and observer notifications)
    request_storage.add_request(request_data)

    return response


MAX_STORED_REQUESTS = 200


class WebUI:
    """Web UI module for the dd-apm-test-agent"""

    def __init__(self, agent: Any, config: Dict = None) -> None:
        self.agent = agent
        self.config = config or {}

        # Initialize or reconfigure global request storage with max requests from config
        global request_storage
        max_requests = self.config.get("max_requests", 200)
        if request_storage is None:
            request_storage = RequestStorage(max_requests=max_requests)
        else:
            # Update existing storage limit if needed
            request_storage._max_requests = max_requests

        # Track SSE connections for real-time updates
        self._sse_connections: weakref.WeakSet = weakref.WeakSet()

        # Register as observer for request notifications
        request_storage.add_observer(self)

        # Set up Jinja2 template environment
        templates_dir = Path(__file__).parent / "templates"
        self.jinja_env = Environment(loader=FileSystemLoader(str(templates_dir)), autoescape=True)

        # Add custom filters
        def timestamp_format(timestamp):
            """Format timestamp for display"""
            dt = datetime.datetime.fromtimestamp(timestamp)
            return dt.strftime("%Y-%m-%d %H:%M:%S")

        self.jinja_env.filters["timestamp_format"] = timestamp_format

    async def notify_request(self, request_data: Dict) -> None:
        """RequestObserver implementation - notify SSE connections of new requests"""
        if not self._sse_connections:
            return

        # Process the request data for WebUI display
        processed_request = self._process_single_request(request_data)
        if not processed_request:
            return

        message = json.dumps(
            {
                "type": "new_request",
                "request": processed_request,
                "total_count": len(request_storage),
            }
        )

        # Send to all connected SSE clients
        dead_connections = []
        for connection in self._sse_connections:
            try:
                await connection.write(f"data: {message}\n\n".encode())
            except Exception:
                dead_connections.append(connection)

        # Clean up dead connections
        for connection in dead_connections:
            self._sse_connections.discard(connection)

    def get_requests_from_agent(self) -> List[dict]:
        """Get processed request data from unified request storage"""
        processed_requests = []

        # Get all requests from unified storage (already in most recent first order)
        all_requests = request_storage.get_all_requests()[:MAX_STORED_REQUESTS]

        for req_data in all_requests:
            processed_request = self._process_single_request(req_data)
            if processed_request:
                processed_requests.append(processed_request)

        return processed_requests

    def _process_single_request(self, req_data: Dict) -> Optional[Dict]:
        """Process a single request data dict into WebUI format"""
        try:
            # Process request and response bodies using utility
            request_body, request_body_is_binary = BodyProcessor.process_body(
                req_data["request_body"], req_data["content_type"]
            )
            response_body, response_body_is_binary = BodyProcessor.process_body(
                req_data["response"]["body"],
                req_data["response"]["headers"].get("Content-Type", ""),
            )

            # Extract query string from path
            path_parts = req_data["path"].split("?", 1)
            path = path_parts[0]
            query_string = path_parts[1] if len(path_parts) > 1 else ""

            # Parse query parameters into a dict for template rendering
            query_params = {}
            if query_string:
                query_params = urllib.parse.parse_qs(query_string, keep_blank_values=True)

            # Check if this is a trace request and process trace data
            trace_data = None
            if path in ["/v0.4/traces", "/v0.5/traces", "/v0.7/traces", "/v1.0/traces"]:
                trace_data = self._process_middleware_trace_data(req_data, path)

            return {
                "method": req_data["method"],
                "path": path,
                "query_string": query_string,
                "query_params": query_params,
                "headers": req_data["headers"],
                "content_type": req_data["content_type"],
                "content_length": len(req_data["request_body"]) if req_data["request_body"] else 0,
                "remote_addr": req_data["remote_addr"],
                "timestamp": req_data["timestamp"],
                "session_token": req_data["headers"].get("X-Datadog-Test-Session-Token"),
                "body": request_body,
                "body_is_binary": request_body_is_binary,
                "trace_data": trace_data,
                "response": {
                    "status": req_data["response"]["status"],
                    "headers": req_data["response"]["headers"],
                    "content_type": req_data["response"]["headers"].get("Content-Type", ""),
                    "body": response_body,
                    "body_is_binary": response_body_is_binary,
                },
                "duration_ms": req_data["duration_ms"],
            }
        except Exception as e:
            log.debug(f"Failed to process captured request: {e}")
            return None

    def _get_request_body(self, req) -> str:
        """Extract and format request body for display"""
        if "_testagent_data" not in req:
            return ""

        data = req["_testagent_data"]
        content_type = req.content_type or ""

        if "msgpack" in content_type.lower():
            # For binary data, show as base64
            import base64

            return base64.b64encode(data).decode("ascii")
        else:
            # For text data, decode as UTF-8
            try:
                return data.decode("utf-8", errors="replace")
            except (UnicodeDecodeError, AttributeError):
                return str(data)

    def _get_basic_trace_info(self, req):
        """Get basic trace info without full decoding for request list"""
        if not self._is_trace_request(req):
            return None

        # Just return basic info indicating this is a trace request
        # The actual decoding will happen when viewing the trace details
        return {
            "is_trace_request": True,
            "path": req.path,
            "trace_count": "?",  # Unknown until decoded
            "span_count": "?",  # Unknown until decoded
            "traces": None,
            "trace_data_b64": "",  # Will be filled when actually needed
        }

    def _get_trace_data(self, req):
        """Extract and process trace data for trace requests"""
        if not self._is_trace_request(req):
            return None

        # Get raw data
        if "_testagent_data" not in req:
            return None

        raw_data = req["_testagent_data"]
        content_type = req.content_type or ""

        return TraceProcessor.process_traces(raw_data, content_type, req.path, suppress_errors=False)

    def _process_middleware_trace_data(self, req_data, path):
        """Process trace data from middleware-captured request data"""
        raw_data = req_data.get("request_body", b"")
        content_type = req_data.get("content_type", "")

        return TraceProcessor.process_traces(raw_data, content_type, path, suppress_errors=True)

    def _is_trace_request(self, req) -> bool:
        """Check if request is a trace request based on path"""
        trace_paths = ["/v0.4/traces", "/v0.5/traces", "/v0.7/traces", "/v1.0/traces"]
        return req.path in trace_paths

    def _clean_trace_data_for_json(self, traces):
        """Clean trace data to ensure JSON serializability"""
        import json

        def clean_value(obj):
            if isinstance(obj, (int, float, str, bool)) or obj is None:
                return obj
            elif isinstance(obj, bytes):
                # Convert bytes to base64 string
                import base64

                try:
                    return base64.b64encode(obj).decode("ascii")
                except Exception:
                    return "[Binary data]"
            elif isinstance(obj, dict):
                return {str(k): clean_value(v) for k, v in obj.items()}
            elif isinstance(obj, (list, tuple)):
                return [clean_value(item) for item in obj]
            else:
                # For any other type, convert to string
                try:
                    return str(obj)
                except Exception:
                    return "[Unserializable object]"

        try:
            cleaned = clean_value(traces)
            # Test JSON serializability
            json.dumps(cleaned)
            return cleaned
        except Exception:
            # Failed to clean trace data
            return []

    def make_app(self) -> web.Application:
        """Create the web UI application"""
        app = web.Application()

        # Set up routes
        app.add_routes(
            [
                web.get("/", self.handle_dashboard),
                web.get("/requests", self.handle_requests),
                web.get("/requests/stream", self.handle_requests_sse),
                web.post("/requests/clear", self.handle_clear_requests),
                web.get("/requests/download", self.handle_download_requests),
                web.get("/traces", self.handle_requests),  # Redirect old traces URL
                web.get("/traces/{trace_id}", self.handle_trace_detail),
                web.get("/config", self.handle_config),
                web.post("/config/create", self.handle_config_create),
                web.post("/config/update", self.handle_config_update),
                web.post("/config/create_path", self.handle_config_create_path),
                web.post("/config/clear", self.handle_config_clear),
                web.get("/tracerflares", self.handle_tracer_flares),
                web.post("/tracerflares/start", self.handle_start_flare),
                web.post("/tracerflares/stop", self.handle_stop_flare),
                web.get("/tracerflares/download", self.handle_download_tracer_flare),
                web.get("/snapshots", self.handle_snapshots),
                web.get("/snapshots/{filename}", self.handle_snapshot_detail),
                # HTMX endpoints for server-side processing
                web.post("/api/render-waterfall", self.handle_render_waterfall),
                web.post("/api/render-json", self.handle_render_json),
                # Static files
                web.static("/static", Path(__file__).parent / "static"),
            ]
        )

        return app

    async def handle_dashboard(self, request: web.Request) -> web.Response:
        """Handle dashboard page"""
        template = self.jinja_env.get_template("dashboard.html")

        # Get server configuration information

        # Get server configuration (not runtime status)
        enabled_servers = {
            "web_ui": True,  # If we're serving this page, Web UI is enabled
            "apm_server": True,  # Always enabled in the main app
            "otlp_http": True,  # Always enabled
            "otlp_grpc": True,  # Always enabled
        }

        # Get configuration from main app config stored in agent
        main_config = self.config
        agent_url = main_config.get("agent_url", "")
        is_proxying = bool(agent_url)

        # Get actual port configuration from main app
        actual_apm_port = main_config.get("port", 8126)
        actual_otlp_http_port = main_config.get("otlp_http_port", 4318)
        actual_otlp_grpc_port = main_config.get("otlp_grpc_port", 4317)

        content = template.render(
            title="Dashboard",
            total_requests=len(request_storage),
            # Server configuration
            web_ui_port=self.config.get("web_ui_port", 8080),
            apm_port=actual_apm_port,
            otlp_http_port=actual_otlp_http_port,
            otlp_grpc_port=actual_otlp_grpc_port,
            enabled_servers=enabled_servers,
            is_proxying=is_proxying,
            agent_url=agent_url,
            snapshot_dir=main_config.get("snapshot_dir", "snapshots"),
            vcr_enabled=bool(main_config.get("vcr_cassettes_directory")),
            error_responses_disabled=main_config.get("disable_error_responses", False),
            max_requests=main_config.get("max_requests", 200),
        )
        return web.Response(text=content, content_type="text/html")

    async def handle_requests(self, request: web.Request) -> web.Response:
        """Handle requests page - live view of all requests"""
        template = self.jinja_env.get_template("requests.html")

        # Get processed requests from agent
        request_data = self.get_requests_from_agent()

        content = template.render(
            requests=request_data,
            total_requests=len(request_storage),
        )
        return web.Response(text=content, content_type="text/html")

    async def handle_trace_detail(self, request: web.Request) -> web.Response:
        """Handle individual trace detail page"""
        trace_id = int(request.match_info["trace_id"])
        template = self.jinja_env.get_template("trace_detail.html")
        try:
            trace = await self.agent._trace_by_trace_id(trace_id)
            content = template.render(
                title=f"Trace {trace_id}",
                trace_id=trace_id,
                trace=trace,
            )
        except KeyError:
            content = template.render(
                title=f"Trace {trace_id}",
                trace_id=trace_id,
                trace=None,
                error="Trace not found",
            )
        return web.Response(text=content, content_type="text/html")

    async def handle_config(self, request: web.Request) -> web.Response:
        """Handle config page"""
        template = self.jinja_env.get_template("config.html")

        # Get selected token from query parameter
        selected_token = request.query.get("token", "")
        if selected_token == "null" or selected_token == "":
            selected_token = None

        # Get available session tokens from stored requests
        session_tokens = set()
        for req_info in self.get_requests_from_agent():
            token = req_info.get("session_token")
            if token:
                session_tokens.add(token)

        # Always include None (default) option
        all_tokens = [None] + sorted(session_tokens)

        # Get current remote config data for selected token
        current_config = {}
        try:
            current_config = await self.agent._rc_server.get_config_response(selected_token)
            if not current_config:
                current_config = {}
        except Exception:
            current_config = {}

        # Get all configs for display
        all_configs = {}
        for token in all_tokens:
            try:
                token_config = await self.agent._rc_server.get_config_response(token)
                if token_config:
                    all_configs[str(token)] = token_config
            except Exception:
                pass

        content = template.render(
            title="Configuration",
            session_tokens=all_tokens,
            selected_token=selected_token,
            current_config_json=json.dumps(current_config, indent=2) if current_config else "{}",
            config_data=json.dumps(all_configs, indent=2) if all_configs else "{}",
        )
        return web.Response(text=content, content_type="text/html")

    async def handle_config_create(self, request: web.Request) -> web.Response:
        """Handle creating a new remote config response"""
        try:
            data = await request.post()
            token = data.get("token") or None
            config_data = data.get("config_data", "{}")

            # Parse and validate JSON
            try:
                parsed_config = json.loads(config_data)
            except json.JSONDecodeError as e:
                return web.json_response({"error": f"Invalid JSON: {e}"}, status=400)

            self.agent._rc_server.create_config_response(token, parsed_config)
            return web.json_response({"status": "success", "message": "Config created successfully"})

        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_config_update(self, request: web.Request) -> web.Response:
        """Handle updating a remote config response"""
        try:
            data = await request.post()
            token = data.get("token") or None
            config_data = data.get("config_data", "{}")

            # Parse and validate JSON
            try:
                parsed_config = json.loads(config_data)
            except json.JSONDecodeError as e:
                return web.json_response({"error": f"Invalid JSON: {e}"}, status=400)

            self.agent._rc_server.update_config_response(token, parsed_config)
            return web.json_response({"status": "success", "message": "Config updated successfully"})

        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_config_create_path(self, request: web.Request) -> web.Response:
        """Handle creating a remote config path response"""
        try:
            data = await request.post()
            token = data.get("token") or None
            path = data.get("path", "")
            message = data.get("message", "{}")

            if not path:
                return web.json_response({"error": "Path is required"}, status=400)

            # Validate and parse message JSON
            try:
                parsed_message = json.loads(message)
            except json.JSONDecodeError as e:
                return web.json_response({"error": f"Invalid message JSON: {e}"}, status=400)

            self.agent._rc_server.create_config_path_response(token, path, parsed_message)
            return web.json_response({"status": "success", "message": "Config path created successfully"})

        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_config_clear(self, request: web.Request) -> web.Response:
        """Handle clearing remote config for a token"""
        try:
            data = await request.post()
            token = data.get("token") or None

            # Clear by creating empty response
            self.agent._rc_server.create_config_response(token, {})
            return web.json_response({"status": "success", "message": "Config cleared successfully"})

        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_tracer_flares(self, request: web.Request) -> web.Response:
        """Handle tracer flares page"""
        template = self.jinja_env.get_template("tracer_flares.html")

        # Get ALL tracer flares regardless of session token
        tracer_flares = []
        try:
            # Get all flares by getting flares for None (default session) and then all other sessions
            all_flares = []

            # Get flares for default session (None)
            default_flares = await self.agent._tracerflares_by_session(None)
            for flare in default_flares:
                flare["session_token"] = None  # Mark session token for display
            all_flares.extend(default_flares)

            # Get flares for all other session tokens
            session_tokens = set()
            for req_data in request_storage.get_all_requests():
                token = req_data.get("headers", {}).get("X-Datadog-Test-Session-Token")
                if token:
                    session_tokens.add(token)

            for token in session_tokens:
                token_flares = await self.agent._tracerflares_by_session(token)
                for flare in token_flares:
                    flare["session_token"] = token  # Mark session token for display
                all_flares.extend(token_flares)

            tracer_flares = all_flares
        except Exception as e:
            print(f"Error getting tracer flares: {e}")

        # Check for active flare - check all active flares
        active_flares = getattr(self.agent, "_active_flares", {})
        active_flare = None
        # Find any active flare (there should only be one at a time)
        for flare_info in active_flares.values():
            active_flare = flare_info
            break

        content = template.render(
            title="Tracer Flares",
            tracer_flares=tracer_flares,
            total_flares=len(tracer_flares),
            active_flare=active_flare,
        )
        return web.Response(text=content, content_type="text/html")

    async def handle_start_flare(self, request: web.Request) -> web.Response:
        """Handle starting a tracer flare collection"""
        try:
            data = await request.post()
            session_token = data.get("token") or None

            # Generate unique UUID for this flare request
            import uuid

            flare_uuid = str(uuid.uuid4())

            # Step 1: Send AGENT_CONFIG to enable debug logging
            debug_config = {"config": {"log_level": "debug"}}
            self.agent._rc_server.create_config_path_response(
                session_token, "datadog/2/AGENT_CONFIG/flare_debug/config", debug_config
            )

            # Store the active flare info
            if not hasattr(self.agent, "_active_flares"):
                self.agent._active_flares = {}

            import time

            self.agent._active_flares[session_token or "default"] = {
                "uuid": flare_uuid,
                "start_time": time.time(),
                "case_id": str(int(time.time())),  # Pure numeric timestamp
                "hostname": "test-agent",
                "user_handle": "test@example.com",
            }

            return web.json_response(
                {
                    "status": "success",
                    "message": "Tracer flare collection started",
                    "uuid": flare_uuid,
                }
            )

        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_stop_flare(self, request: web.Request) -> web.Response:
        """Handle stopping a tracer flare collection and triggering upload"""
        try:
            data = await request.post()
            session_token = data.get("token") or None

            # Check if there's an active flare
            if not hasattr(self.agent, "_active_flares"):
                return web.json_response({"error": "No active flare collection"}, status=400)

            active_flares = getattr(self.agent, "_active_flares", {})
            flare_key = session_token or "default"

            if flare_key not in active_flares:
                return web.json_response({"error": "No active flare for this session"}, status=400)

            flare_info = active_flares[flare_key]

            # Step 2: Send AGENT_TASK to trigger flare upload
            task_config = {
                "task_type": "tracer_flare",
                "uuid": flare_info["uuid"],
                "args": {
                    "case_id": flare_info["case_id"],
                    "hostname": flare_info["hostname"],
                    "user_handle": flare_info["user_handle"],
                },
            }

            self.agent._rc_server.create_config_path_response(
                session_token, "datadog/2/AGENT_TASK/flare_upload/config", task_config
            )

            # Remove from active flares
            del active_flares[flare_key]

            return web.json_response(
                {
                    "status": "success",
                    "message": "Tracer flare upload triggered",
                    "case_id": flare_info["case_id"],
                }
            )

        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_download_tracer_flare(self, request: web.Request) -> web.Response:
        """Handle downloading a tracer flare ZIP file"""
        try:
            case_id = request.query.get("case_id")

            if not case_id:
                return web.json_response({"error": "case_id parameter required"}, status=400)

            # Get ALL tracer flares from all sessions
            all_flares = []

            # Get flares for default session (None)
            default_flares = await self.agent._tracerflares_by_session(None)
            all_flares.extend(default_flares)

            # Get flares for all other session tokens
            session_tokens = set()
            for req_data in request_storage.get_all_requests():
                token = req_data.get("headers", {}).get("X-Datadog-Test-Session-Token")
                if token:
                    session_tokens.add(token)

            for token in session_tokens:
                token_flares = await self.agent._tracerflares_by_session(token)
                all_flares.extend(token_flares)

            # Debug logging
            # Looking for case_id in flares
            # Found flares
            # Find the flare with matching case_id
            target_flare = None
            for flare in all_flares:
                if flare.get("case_id") == case_id:
                    target_flare = flare
                    break

            if not target_flare:
                # Create detailed error message with available case_ids
                available_cases = [f"'{flare.get('case_id')}'" for flare in all_flares]
                error_msg = f"Flare not found. Looking for '{case_id}', available: {available_cases}"
                # Error processing flare
                return web.json_response({"error": error_msg}, status=404)

            if "flare_file" not in target_flare:
                return web.json_response({"error": "No flare file in this flare"}, status=404)

            try:
                # Decode base64 flare file data
                import base64

                flare_data = base64.b64decode(target_flare["flare_file"])

                # Return as ZIP file download
                return web.Response(
                    body=flare_data,
                    content_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="tracer_flare_{case_id}.zip"'},
                )
            except Exception as decode_error:
                return web.json_response({"error": f"Error decoding flare file: {decode_error}"}, status=500)

        except Exception as e:
            return web.json_response({"error": str(e)}, status=500)

    async def handle_snapshots(self, request: web.Request) -> web.Response:
        """Handle snapshots page"""
        template = self.jinja_env.get_template("snapshots.html")

        # Get snapshot directory from main app config
        main_config = self.config
        snapshot_dir = main_config.get("snapshot_dir", "snapshots")
        snapshots = []

        try:
            snapshot_path = Path(snapshot_dir)
            if snapshot_path.exists() and snapshot_path.is_dir():
                # Get all JSON files in the snapshot directory
                json_files = list(snapshot_path.glob("*.json"))
                json_files.sort()  # Sort alphabetically

                for file_path in json_files:
                    try:
                        stat = file_path.stat()
                        snapshots.append(
                            {
                                "filename": file_path.name,
                                "size": stat.st_size,
                                "modified": stat.st_mtime,
                            }
                        )
                    except (OSError, IOError):
                        # Skip files we can't stat
                        continue
        except Exception as e:
            # Handle directory access errors
            error_msg = f"Error accessing snapshot directory: {e}"
        else:
            error_msg = None

        content = template.render(
            title="Snapshots",
            snapshots=snapshots,
            snapshot_dir=snapshot_dir,
            error=error_msg,
        )
        return web.Response(text=content, content_type="text/html")

    async def handle_snapshot_detail(self, request: web.Request) -> web.Response:
        """Handle individual snapshot detail page"""
        filename = request.match_info["filename"]
        template = self.jinja_env.get_template("snapshot_detail.html")

        # Get snapshot directory from main app config
        main_config = self.config
        snapshot_dir = main_config.get("snapshot_dir", "snapshots")

        try:
            snapshot_path = Path(snapshot_dir) / filename

            # Security check: ensure the file is within the snapshot directory
            snapshot_path = snapshot_path.resolve()
            allowed_dir = Path(snapshot_dir).resolve()
            if not str(snapshot_path).startswith(str(allowed_dir)):
                raise ValueError("File path not allowed")

            if not snapshot_path.exists() or not snapshot_path.is_file():
                raise FileNotFoundError("Snapshot file not found")

            # Read and parse JSON content
            with open(snapshot_path, "r", encoding="utf-8") as f:
                raw_content = f.read()

            try:
                parsed_data = json.loads(raw_content)
                # Pretty-format the JSON
                formatted_content = json.dumps(parsed_data, indent=2, ensure_ascii=False)
                is_valid_json = True

                # Count traces and spans
                trace_count = 0
                span_count = 0
                if isinstance(parsed_data, list):
                    trace_count = len(parsed_data)
                    for trace in parsed_data:
                        if isinstance(trace, list):
                            span_count += len(trace)
                        elif isinstance(trace, dict):
                            span_count += 1
                elif isinstance(parsed_data, dict):
                    # Single trace case
                    trace_count = 1
                    span_count = 1

            except json.JSONDecodeError as e:
                formatted_content = raw_content
                is_valid_json = False
                parse_error = str(e)
                trace_count = 0
                span_count = 0
            else:
                parse_error = None

            # Get file stats
            stat = snapshot_path.stat()
            file_info = {
                "filename": filename,
                "size": stat.st_size,
                "modified": stat.st_mtime,
            }

            content = template.render(
                title=f"Snapshot: {filename}",
                filename=filename,
                file_info=file_info,
                raw_content=formatted_content,
                is_valid_json=is_valid_json,
                parse_error=parse_error,
                trace_count=trace_count,
                span_count=span_count,
                trace_data=json.dumps(parsed_data) if is_valid_json else None,
                error=None,
            )

        except (FileNotFoundError, ValueError, OSError, IOError) as e:
            content = template.render(
                title=f"Snapshot: {filename}",
                filename=filename,
                file_info=None,
                raw_content=None,
                is_valid_json=False,
                parse_error=None,
                error=f"Error loading snapshot: {e}",
            )

        return web.Response(text=content, content_type="text/html")

    async def handle_requests_sse(self, request: web.Request) -> StreamResponse:
        """Handle Server-Sent Events for real-time request updates"""
        response = StreamResponse(
            status=200,
            reason="OK",
            headers={
                "Content-Type": "text/event-stream",
                "Cache-Control": "no-cache",
                "Connection": "keep-alive",
                "Access-Control-Allow-Origin": "*",
            },
        )

        await response.prepare(request)

        # Add this connection to our set
        self._sse_connections.add(response)

        try:
            # Send initial request count from unified storage
            last_count = len(request_storage)
            await response.write(f"data: {json.dumps({'type': 'count', 'count': last_count})}\n\n".encode())

            # Keep connection alive with heartbeats
            # New requests are now sent via notify_new_request from middleware
            while True:
                await asyncio.sleep(5)  # Heartbeat every 5 seconds
                # Send heartbeat (will raise exception if connection is closed)
                await response.write(f"data: {json.dumps({'type': 'heartbeat'})}\n\n".encode())

        except (ConnectionResetError, asyncio.CancelledError, Exception):
            pass
        finally:
            # Clean up connection
            self._sse_connections.discard(response)

        return response

    async def notify_new_request(self, request_info: dict) -> None:
        """Notify all SSE connections about a new request"""
        if not self._sse_connections:
            return

        # Add trace data processing for streaming requests if this is a trace request
        trace_data = None
        if request_info.get("path") in [
            "/v0.4/traces",
            "/v0.5/traces",
            "/v0.7/traces",
            "/v1.0/traces",
        ]:
            try:
                import base64
                import json

                # Parse trace data using the proper decoder based on path
                from .trace import decode_v1
                from .trace import decode_v04
                from .trace import decode_v05
                from .trace import decode_v07

                raw_body = request_info.get("body", "")
                content_type = request_info.get("content_type", "")
                path = request_info.get("path", "")

                if raw_body:
                    # Decode from base64 if needed (msgpack requests are base64 encoded in agent.py)
                    if "msgpack" in content_type.lower():
                        binary_data = base64.b64decode(raw_body)
                    else:
                        binary_data = raw_body.encode("utf-8")

                    # Use the appropriate decoder based on path
                    if path == "/v0.4/traces":
                        traces = decode_v04(content_type, binary_data, False)
                    elif path == "/v0.5/traces":
                        traces = decode_v05(binary_data)
                    elif path == "/v0.7/traces":
                        traces = decode_v07(binary_data)
                    elif path == "/v1.0/traces":
                        traces = decode_v1(binary_data)
                    else:
                        traces = []

                    # Decoded trace chunks
                else:
                    traces = None

                if traces:
                    # Count traces and spans using the same logic as the static version
                    trace_count = len(traces)
                    span_count = sum(len(trace) for trace in traces)

                    # Clean the data for JSON serialization
                    clean_traces = self._clean_trace_data_for_json(traces)

                    # Cleaned trace data

                    # Create base64-encoded version for safe HTML transport
                    trace_data_json = json.dumps(
                        {
                            "traces": clean_traces,
                            "trace_count": trace_count,
                            "span_count": span_count,
                        }
                    )
                    trace_data_b64 = base64.b64encode(trace_data_json.encode("utf-8")).decode("ascii")

                    trace_data = {
                        "traces": clean_traces,
                        "trace_count": trace_count,
                        "span_count": span_count,
                        "trace_data_b64": trace_data_b64,
                    }
            except Exception:
                # Failed to process streaming trace data
                trace_data = None

        # Add trace_data to request_info if present
        if trace_data:
            request_info = {**request_info, "trace_data": trace_data}

        message = json.dumps(
            {
                "type": "new_request",
                "request": request_info,
                "total_count": len(request_storage),
            }
        )

        # Send to all connected clients
        dead_connections = []
        for connection in self._sse_connections:
            try:
                await connection.write(f"data: {message}\n\n".encode())
            except Exception:
                # Connection is dead, mark for removal
                dead_connections.append(connection)

        # Clean up dead connections
        for connection in dead_connections:
            self._sse_connections.discard(connection)

    async def notify_latest_request(self) -> None:
        """Notify all SSE connections about the latest request"""
        if not self._sse_connections:
            return

        try:
            # Get the latest processed request
            processed_requests = self.get_requests_from_agent()
            if not processed_requests:
                return

            latest_request = processed_requests[0]  # Most recent request

            message = json.dumps(
                {
                    "type": "new_request",
                    "request": latest_request,
                    "total_count": len(request_storage),
                }
            )

            # Send to all connected clients
            dead_connections = []
            for connection in self._sse_connections:
                try:
                    await connection.write(f"data: {message}\n\n".encode())
                except Exception:
                    # Connection is dead, mark for removal
                    dead_connections.append(connection)

            # Clean up dead connections
            for connection in dead_connections:
                self._sse_connections.discard(connection)

        except Exception as e:
            log.error(f"Error in notify_latest_request: {e}")

    async def handle_clear_requests(self, request: web.Request) -> web.Response:
        """Handle clearing all stored requests"""
        # Clear unified request storage
        request_storage.clear_requests()
        return web.json_response({"status": "success", "message": "All requests cleared"})

    async def handle_download_requests(self, request: web.Request) -> web.Response:
        """Handle downloading all current requests as JSON"""
        # Use the already processed requests from unified storage
        requests_data = self.get_requests_from_agent()

        # Create JSON response with proper headers for download
        json_content = json.dumps(requests_data, indent=2)
        return web.Response(
            text=json_content,
            content_type="application/json",
            headers={
                "Content-Disposition": "attachment; filename=requests.json",
                "Content-Length": str(len(json_content.encode("utf-8"))),
            },
        )

    async def handle_render_waterfall(self, request):
        """HTMX endpoint: Render waterfall view for trace data"""
        try:
            # Get request data from POST body
            req_data = await request.json()

            # Extract trace data
            trace_data = req_data.get("trace_data")
            if not trace_data or not isinstance(trace_data, dict):
                return web.Response(
                    text='<div class="empty-state">No trace data available</div>',
                    content_type="text/html",
                )

            # Use existing trace processing
            traces = trace_data.get("traces", [])
            if not traces:
                return web.Response(
                    text='<div class="empty-state">No trace data available for waterfall view</div>',
                    content_type="text/html",
                )

            # Render waterfall HTML server-side
            html = self._render_waterfall_html(traces)
            return web.Response(text=html, content_type="text/html")

        except Exception as e:
            log.error(f"Error rendering waterfall: {e}")
            return web.Response(
                text=f'<div class="error-message">Error generating waterfall view: {str(e)}</div>',
                content_type="text/html",
            )

    async def handle_render_json(self, request):
        """HTMX endpoint: Render pretty-printed JSON for request body"""
        try:
            # Get request data from POST body
            req_data = await request.json()

            # Extract body data and content type
            body_data = req_data.get("body_data", "")
            content_type = req_data.get("content_type", "")

            if not body_data:
                return web.Response(
                    text='<div class="empty-state">No body data</div>',
                    content_type="text/html",
                )

            # Process the body data
            processed_body, is_binary = BodyProcessor.process_body(
                body_data.encode("utf-8") if isinstance(body_data, str) else body_data,
                content_type,
            )

            if is_binary:
                html = f'<pre class="json-display binary">{processed_body}</pre>'
            else:
                # Try to pretty-print as JSON
                try:
                    parsed_json = json.loads(processed_body)
                    pretty_json = json.dumps(parsed_json, indent=2)
                    html = f'<pre class="json-display">{pretty_json}</pre>'
                except json.JSONDecodeError:
                    # Not JSON, display as text
                    html = f'<pre class="json-display text">{processed_body}</pre>'

            return web.Response(text=html, content_type="text/html")

        except Exception as e:
            log.error(f"Error rendering JSON: {e}")
            return web.Response(
                text=f'<div class="error-message">Error processing body data: {str(e)}</div>',
                content_type="text/html",
            )

    def _render_waterfall_html(self, traces: List) -> str:
        """Render waterfall HTML from trace data"""
        if not traces:
            return '<div class="empty-state">No trace data available</div>'

        html = '<div class="waterfall-traces">'

        for trace_index, trace in enumerate(traces):
            if not trace or not isinstance(trace, list):
                continue

            # Process spans
            valid_spans = [span for span in trace if span and isinstance(span, dict)]
            if not valid_spans:
                continue

            # Calculate timing
            min_start = min(span.get("start", 0) for span in valid_spans)
            max_end = max(span.get("start", 0) + span.get("duration", 0) for span in valid_spans)
            total_duration = max_end - min_start

            if total_duration == 0:
                total_duration = max(span.get("duration", 0) for span in valid_spans)

            trace_id = valid_spans[0].get("trace_id", trace_index)

            html += f"""
            <div class="waterfall-trace">
                <div class="trace-header">
                    <div class="trace-header-left">
                        <h4>Trace {trace_id}</h4>
                    </div>
                    <span class="trace-duration">{self._format_duration(total_duration)}</span>
                </div>
                <div class="spans-timeline">
            """

            # Sort spans and render
            sorted_spans = sorted(valid_spans, key=lambda s: s.get("start", 0))
            span_hierarchy = self._build_span_hierarchy(sorted_spans)

            for span_info in span_hierarchy:
                html += self._render_span_html(span_info, min_start, total_duration, 0)

            html += "</div></div>"

        html += "</div>"
        return html

    def _build_span_hierarchy(self, spans: List[Dict]) -> List[Dict]:
        """Build hierarchical span structure"""
        # Create span lookup
        span_lookup = {span.get("span_id"): span for span in spans}
        root_spans = []

        for span in spans:
            parent_id = span.get("parent_id")
            if not parent_id or parent_id not in span_lookup:
                # Root span
                root_spans.append({"span": span, "children": self._get_children(span, spans)})

        return root_spans

    def _get_children(self, parent_span: Dict, all_spans: List[Dict]) -> List[Dict]:
        """Get child spans recursively"""
        parent_id = parent_span.get("span_id")
        children = []

        for span in all_spans:
            if span.get("parent_id") == parent_id and span.get("span_id") != parent_id:
                children.append({"span": span, "children": self._get_children(span, all_spans)})

        return sorted(children, key=lambda c: c["span"].get("start", 0))

    def _render_span_html(self, span_info: Dict, min_start: int, total_duration: int, depth: int) -> str:
        """Render HTML for a single span and its children"""
        span = span_info["span"]
        children = span_info.get("children", [])

        # Calculate positioning
        start_time = span.get("start", 0)
        duration = span.get("duration", 0)

        if total_duration > 0:
            left_percent = ((start_time - min_start) / total_duration) * 100
            width_percent = (duration / total_duration) * 100
        else:
            left_percent = 0
            width_percent = 100

        # Generate span classes
        span_class = "waterfall-span"
        if span.get("error"):
            span_class += " error"

        service = span.get("service", "unknown")
        operation = span.get("name", "unknown")

        indent_style = f"margin-left: {depth * 20}px;"
        bar_style = f"left: {left_percent}%; width: {max(width_percent, 0.5)}%;"

        html = f"""
        <div class="{span_class}" style="{indent_style}">
            <div class="span-info">
                <span class="service-name">{service}</span>
                <span class="operation-name">{operation}</span>
                <span class="span-duration">{self._format_duration(duration)}</span>
            </div>
            <div class="span-bar" style="{bar_style}"></div>
        </div>
        """

        # Add children
        for child in children:
            html += self._render_span_html(child, min_start, total_duration, depth + 1)

        return html

    def _format_duration(self, duration_ns: int) -> str:
        """Format duration from nanoseconds to human readable"""
        if duration_ns < 1000:
            return f"{duration_ns}ns"
        elif duration_ns < 1000000:
            return f"{duration_ns / 1000:.1f}μs"
        elif duration_ns < 1000000000:
            return f"{duration_ns / 1000000:.1f}ms"
        else:
            return f"{duration_ns / 1000000000:.2f}s"
