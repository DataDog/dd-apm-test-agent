"""Send messages to local coding-agent sessions."""

import asyncio
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
from typing import Iterator
from typing import List

from aiohttp import web

from ddapm_test_agent.cors import with_cors

from .app_names import CLAUDE_CODE_ML_APP
from .app_names import PI_CODING_AGENT_ML_APP

COMMAND_TIMEOUT = 300


def _codex_socket_paths() -> Iterator[Path]:
    codex_home = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex")
    yield codex_home / "app-server-control" / "app-server-control.sock"
    roots = dict.fromkeys((tempfile.gettempdir(), "/tmp"))
    for root in roots:
        for directory, _, filenames in os.walk(root):
            if "rc.sock" in filenames:
                yield Path(directory) / "rc.sock"


def _codex_remote() -> str:
    if sys.platform == "win32":
        raise web.HTTPNotImplemented(text="Codex Unix-socket sessions require macOS or Linux.")
    for path in _codex_socket_paths():
        try:
            if not path.is_socket():
                continue
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(0.2)
                connection.connect(str(path))
            return "unix://" + str(path)
        except OSError:
            continue
    raise web.HTTPServiceUnavailable(
        text="No reachable Codex app-server socket found. Checked CODEX_HOME (default ~/.codex) "
        "and temporary rc.sock files. Check that Codex and Lapdog use the same user and CODEX_HOME."
    )


class HeadlessCodingAgentInteractionsAPI:
    """HTTP API for sending messages through coding-agent command-line tools."""

    async def handle_send(self, request: web.Request) -> web.Response:
        try:
            payload = await request.json()
        except (ValueError, UnicodeDecodeError):
            raise web.HTTPBadRequest(text="Expected a JSON object.")
        if not isinstance(payload, dict):
            raise web.HTTPBadRequest(text="Expected a JSON object.")
        for field in ("coding_agent", "message", "session_id"):
            value = payload.get(field)
            if not isinstance(value, str) or not value.strip() or "\0" in value:
                raise web.HTTPBadRequest(text=f"{field} must be a non-empty string without null characters.")

        agent_names = {
            os.environ.get("DD_CODEX_ML_APP", "codex"): "codex",
            CLAUDE_CODE_ML_APP: "claude",
            PI_CODING_AGENT_ML_APP: "pi",
        }
        agent = agent_names.get(payload["coding_agent"])
        if agent is None:
            raise web.HTTPBadRequest(text=f"coding_agent must match a span ml_app: {', '.join(agent_names)}.")
        launcher = "lapdog" if agent == "claude" else agent
        binary = shutil.which(launcher)
        if binary is None:
            raise web.HTTPServiceUnavailable(text=f"{launcher} was not found on the server PATH.")
        if sys.platform == "win32" and Path(binary).suffix.lower() in (".cmd", ".bat"):
            raise web.HTTPNotImplemented(
                text="A native executable is required; Windows batch launchers are not supported."
            )

        session_id, message = payload["session_id"], payload["message"]
        args: List[str]
        if agent == "codex":
            remote = await asyncio.to_thread(_codex_remote)
            args = ["--remote", remote, "queue", "--thread", session_id, "--message", message]
        elif agent == "claude":
            args = ["claude", "--resume", session_id, "-p", message]
        else:
            args = ["--session", session_id, "--print", message]

        try:
            process = await asyncio.create_subprocess_exec(
                binary,
                *args,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        except OSError:
            raise web.HTTPServiceUnavailable(text=f"Could not start {agent}.")
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=COMMAND_TIMEOUT)
        except (asyncio.TimeoutError, asyncio.CancelledError) as error:
            if process.returncode is None:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
            await process.wait()
            if isinstance(error, asyncio.CancelledError):
                raise
            raise web.HTTPGatewayTimeout(text=f"{agent} exceeded the {COMMAND_TIMEOUT}-second limit.")

        return web.json_response(
            {
                "coding_agent": payload["coding_agent"],
                "session_id": session_id,
                "exit_code": process.returncode,
                "stdout": stdout.decode("utf-8", errors="replace"),
                "stderr": stderr.decode("utf-8", errors="replace"),
            },
            status=200 if process.returncode == 0 else 502,
        )

    def get_routes(self) -> List[web.RouteDef]:
        """Return the routes for this API."""
        handler = with_cors(self.handle_send)
        return [
            web.post("/lapdog/coding_agent/send", handler),
            web.options("/lapdog/coding_agent/send", handler),
        ]
