import io
import json
import threading
import time
from typing import Any
from typing import Dict

import pytest
import requests

from ddapm_test_agent.mcp_wrapper import _handle_mcp_request
from ddapm_test_agent.mcp_wrapper import _read_mcp_message
from ddapm_test_agent.mcp_wrapper import _run_http_server
from ddapm_test_agent.mcp_wrapper import _write_mcp_message


class TestMcpFraming:
    def test_read_write_roundtrip(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        buf = io.BytesIO()
        _write_mcp_message(msg, stream=buf)
        buf.seek(0)
        result = _read_mcp_message(stream=buf)
        assert result == msg

    def test_read_eof_raises(self) -> None:
        buf = io.BytesIO(b"")
        with pytest.raises(EOFError):
            _read_mcp_message(stream=buf)

    def test_unicode_content(self) -> None:
        msg: Dict[str, Any] = {"jsonrpc": "2.0", "id": 1, "result": {"text": "hello \u00e9\u00e8\u00ea"}}
        buf = io.BytesIO()
        _write_mcp_message(msg, stream=buf)
        buf.seek(0)
        assert _read_mcp_message(stream=buf) == msg


class TestMcpProtocol:
    def test_initialize(self) -> None:
        resp = _handle_mcp_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
        assert resp is not None
        assert resp["id"] == 1
        assert resp["result"]["protocolVersion"] == "2024-11-05"
        assert "capabilities" in resp["result"]
        assert "serverInfo" in resp["result"]

    def test_notifications_initialized_no_response(self) -> None:
        resp = _handle_mcp_request({"jsonrpc": "2.0", "method": "notifications/initialized"})
        assert resp is None


class TestHttpServer:
    def test_http_server_starts_and_info_responds(self) -> None:
        port = 18126
        thread = threading.Thread(target=_run_http_server, args=(port, None, "datad0g.com"), daemon=True)
        thread.start()
        for _ in range(50):
            try:
                resp = requests.get(f"http://localhost:{port}/info", timeout=1)
                if resp.ok:
                    data = resp.json()
                    assert "version" in data
                    assert "endpoints" in data
                    return
            except requests.ConnectionError:
                pass
            time.sleep(0.1)
        pytest.fail("HTTP server did not start within 5 seconds")
