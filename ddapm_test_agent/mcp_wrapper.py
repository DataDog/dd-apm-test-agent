import asyncio
import json
import logging
import os
import sys
import threading
import time
from typing import Any
from typing import Dict
from typing import Optional

import requests

from aiohttp import web

from ddapm_test_agent.agent import make_app

log = logging.getLogger(__name__)

MCP_PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "dd-llmobs-agent", "version": "1.0"}


def _run_http_server(port: int, dd_api_key: Optional[str], dd_site: str) -> None:
    app = make_app(
        enabled_checks=[],
        log_span_fmt="[{name}]",
        snapshot_dir="",
        snapshot_ci_mode=False,
        snapshot_ignored_attrs=[],
        agent_url="",
        trace_request_delay=0.0,
        suppress_trace_parse_errors=True,
        pool_trace_check_failures=False,
        disable_error_responses=False,
        snapshot_removed_attrs=[],
        snapshot_regex_placeholders={},
        vcr_cassettes_directory="",
        vcr_ci_mode=False,
        vcr_provider_map="",
        vcr_ignore_headers="",
        dd_site=dd_site,
        dd_api_key=dd_api_key,
        disable_llmobs_data_forwarding=(dd_api_key is None),
    )

    async def _start() -> None:
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "0.0.0.0", port)
        await site.start()
        # Block forever
        await asyncio.Event().wait()

    asyncio.run(_start())


def _read_mcp_message(stream: Any = None) -> Dict[str, Any]:
    if stream is None:
        stream = sys.stdin.buffer
    header = b""
    while True:
        byte = stream.read(1)
        if byte == b"":
            raise EOFError("stdin closed")
        header += byte
        if header.endswith(b"\r\n\r\n"):
            break
    content_length = int(header.decode().split(":")[1].strip())
    body = stream.read(content_length)
    return json.loads(body)  # type: ignore[no-any-return]


def _write_mcp_message(msg: Dict[str, Any], stream: Any = None) -> None:
    if stream is None:
        stream = sys.stdout.buffer
    body = json.dumps(msg).encode()
    frame = f"Content-Length: {len(body)}\r\n\r\n".encode() + body
    stream.write(frame)
    stream.flush()


def _handle_mcp_request(msg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    method = msg.get("method", "")
    msg_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {},
                "serverInfo": SERVER_INFO,
            },
        }
    elif method == "notifications/initialized":
        return None
    elif method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": []},
        }
    elif method == "ping":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {},
        }
    else:
        log.warning("Unknown MCP method: %s", method)
        return None


def _mcp_stdio_loop() -> None:
    while True:
        try:
            msg = _read_mcp_message()
        except EOFError:
            break
        resp = _handle_mcp_request(msg)
        if resp is not None:
            _write_mcp_message(resp)


def main() -> None:
    port = int(os.environ.get("PORT", "8126"))
    dd_api_key = os.environ.get("DD_API_KEY")
    dd_site = os.environ.get("DD_SITE", "datad0g.com")

    # Redirect all logging to stderr to avoid corrupting MCP framing on stdout
    logging.basicConfig(level=logging.INFO, stream=sys.stderr)

    log.info("Starting HTTP server on port %d", port)
    thread = threading.Thread(target=_run_http_server, args=(port, dd_api_key, dd_site), daemon=True)
    thread.start()

    # Poll until the HTTP server is ready
    for _ in range(100):
        try:
            resp = requests.get(f"http://localhost:{port}/info", timeout=1)
            if resp.ok:
                break
        except requests.ConnectionError:
            pass
        time.sleep(0.1)
    else:
        log.error("HTTP server failed to start on port %d", port)
        sys.exit(1)

    log.info("HTTP server ready, entering MCP loop")
    _mcp_stdio_loop()


if __name__ == "__main__":
    main()
