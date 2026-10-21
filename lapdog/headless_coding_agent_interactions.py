"""Send messages to local coding-agent sessions."""

import asyncio
from dataclasses import dataclass
from dataclasses import field
import os
from pathlib import Path
import shutil
import socket
import sys
import tempfile
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
import uuid

from aiohttp import WSMsgType
from aiohttp import web

from ddapm_test_agent.cors import with_cors

from .app_names import CLAUDE_CODE_ML_APP
from .app_names import PI_CODING_AGENT_ML_APP
from .claude_hooks import ClaudeHooksAPI

COMMAND_TIMEOUT = 300
DELIVERY_TIMEOUT = 10


@dataclass
class _PiConnection:
    socket: web.WebSocketResponse
    pending: Dict[str, asyncio.Future[None]] = field(default_factory=dict)


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

    def __init__(self, hooks_api: Optional[ClaudeHooksAPI] = None) -> None:
        self._hooks_api = hooks_api
        self._connections: Dict[str, _PiConnection] = {}

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
        session_id, message = payload["session_id"], payload["message"]
        if agent == "pi":
            message_id = await self._send_pi(session_id, message)
            return web.json_response(
                {
                    "coding_agent": payload["coding_agent"],
                    "session_id": session_id,
                    "message_id": message_id,
                    "status": "accepted",
                },
                status=202,
            )
        launcher = "lapdog" if agent == "claude" else agent
        binary = shutil.which(launcher)
        if binary is None:
            raise web.HTTPServiceUnavailable(text=f"{launcher} was not found on the server PATH.")
        if sys.platform == "win32" and Path(binary).suffix.lower() in (".cmd", ".bat"):
            raise web.HTTPNotImplemented(
                text="A native executable is required; Windows batch launchers are not supported."
            )

        args: List[str]
        if agent == "codex":
            remote = await asyncio.to_thread(_codex_remote)
            args = ["--remote", remote, "queue", "--thread", session_id, "--message", message]
        else:
            args = ["claude", "--resume", session_id, "-p", message]

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

    async def handle_pi_connect(self, request: web.Request) -> web.WebSocketResponse:
        socket = web.WebSocketResponse(heartbeat=15, max_msg_size=16 * 1024)
        await socket.prepare(request)
        connection = None
        session_id = ""
        try:
            registration = await socket.receive_json(timeout=5)
            if not isinstance(registration, dict):
                raise ValueError("Invalid registration")
            session_id = registration.get("session_id")
            token = registration.get("token")
            if (
                not isinstance(session_id, str)
                or not isinstance(token, str)
                or not token
                or self._hooks_api is None
                or session_id not in self._hooks_api._session_ids_by_token.get(token, set())
            ):
                await socket.close(code=1008, message=b"Unknown session or launch token")
                return socket
            existing = self._connections.get(session_id)
            if existing is not None and not existing.socket.closed:
                await socket.close(code=1008, message=b"Pi session already connected")
                return socket
            connection = _PiConnection(socket)
            self._connections[session_id] = connection
            await socket.send_json({"type": "ready"})
            async for frame in socket:
                if frame.type != WSMsgType.TEXT:
                    break
                reply = frame.json()
                if not isinstance(reply, dict):
                    raise ValueError("Invalid acknowledgement")
                message_id = reply.get("message_id")
                if not isinstance(message_id, str):
                    raise ValueError("Missing message_id")
                pending = connection.pending.get(message_id)
                if pending is not None and not pending.done():
                    if reply.get("type") == "accepted":
                        pending.set_result(None)
                    elif reply.get("type") == "error":
                        pending.set_exception(web.HTTPBadGateway(text="Pi could not accept the message."))
        except (ValueError, TypeError, asyncio.TimeoutError):
            await socket.close(code=1008, message=b"Invalid Pi connection message")
        finally:
            if connection is not None:
                if self._connections.get(session_id) is connection:
                    del self._connections[session_id]
                for pending in connection.pending.values():
                    if not pending.done():
                        pending.set_exception(
                            web.HTTPServiceUnavailable(
                                text="Pi disconnected before acknowledging delivery. Check the session before retrying."
                            )
                        )
            await socket.close()
        return socket

    async def _send_pi(self, session_id: str, message: str) -> str:
        connection = self._connections.get(session_id)
        if connection is None or connection.socket.closed:
            raise web.HTTPConflict(text="No live Pi connection. Start or reload the session with the Lapdog extension.")
        message_id = uuid.uuid4().hex
        pending = asyncio.get_running_loop().create_future()
        connection.pending[message_id] = pending
        try:
            await connection.socket.send_json({"type": "message", "message_id": message_id, "content": message})
            await asyncio.wait_for(pending, timeout=DELIVERY_TIMEOUT)
        except asyncio.TimeoutError:
            raise web.HTTPGatewayTimeout(
                text="Pi did not acknowledge delivery. The message may have arrived; check the session before retrying."
            )
        except (ConnectionError, RuntimeError):
            raise web.HTTPServiceUnavailable(text="Pi connection closed during delivery.")
        finally:
            connection.pending.pop(message_id, None)
            if not pending.done():
                pending.cancel()
            elif not pending.cancelled():
                pending.exception()
        return message_id

    async def close(self, app: web.Application) -> None:
        await asyncio.gather(
            *(
                connection.socket.close(code=1001, message=b"Lapdog stopping")
                for connection in list(self._connections.values())
            )
        )

    def get_routes(self) -> List[web.RouteDef]:
        """Return the routes for this API."""
        handler = with_cors(self.handle_send)
        return [
            web.get("/lapdog/pi/connect", self.handle_pi_connect),
            web.post("/lapdog/coding_agent/send", handler),
            web.options("/lapdog/coding_agent/send", handler),
        ]
