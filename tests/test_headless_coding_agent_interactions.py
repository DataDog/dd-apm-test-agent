"""Tests for sending messages to local coding agents."""

import asyncio
import socket
from unittest import mock

import pytest
from aiohttp import WSMsgType
from aiohttp import web

from lapdog import headless_coding_agent_interactions
from lapdog.app_names import PI_CODING_AGENT_ML_APP
from lapdog.claude_hooks import ClaudeHooksAPI


@pytest.fixture(autouse=True)
def isolated_codex_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))


@pytest.fixture
def hooks_api(tmp_path):
    hooks = ClaudeHooksAPI()
    hooks._register_session_token("token-a", "session-a")
    hooks._register_session_token("token-b", "session-b")
    for session_id in ("session", "s"):
        session = hooks._get_or_create_session(session_id)
        session.cwd = str(tmp_path)
        session.coding_agent_pids = {"claude": {12345}, "pi": {12345}}
    return hooks


@pytest.fixture
async def client(aiohttp_client, hooks_api, monkeypatch):
    monkeypatch.setattr(headless_coding_agent_interactions, "_process_may_be_running", lambda pid: False)
    app = web.Application()
    api = headless_coding_agent_interactions.HeadlessCodingAgentInteractionsAPI(hooks_api=hooks_api)
    app.add_routes(api.get_routes())
    app.on_shutdown.append(api.close)
    return await aiohttp_client(app)


@pytest.mark.parametrize(
    "agent,binary_name,flags",
    [
        ("codex", "codex", ["--remote", "unix:///tmp/rc.sock", "queue", "--thread", "session", "--message"]),
        ("claude-code", "lapdog", ["claude", "--resume", "session", "-p"]),
        ("pi-coding-agent", "lapdog", ["pi", "--session", "session", "--print"]),
    ],
)
@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize("custom_name", [False, True])
async def test_send(client, agent, binary_name, flags, exit_code, custom_name, monkeypatch, tmp_path):
    if custom_name:
        agent = f"custom-{agent}"
        if binary_name == "codex":
            monkeypatch.setenv("DD_CODEX_ML_APP", agent)
        else:
            setting = "CLAUDE_CODE_ML_APP" if flags[0] == "claude" else "PI_CODING_AGENT_ML_APP"
            monkeypatch.setattr(headless_coding_agent_interactions, setting, agent)
    message = 'hello "world"; $(touch /tmp/should-not-exist)\nnext line'
    process = mock.Mock(returncode=exit_code)
    process.communicate = mock.AsyncMock(return_value=(b"output", b"error"))
    with (
        mock.patch.object(headless_coding_agent_interactions.shutil, "which", return_value="/bin/agent") as which,
        mock.patch.object(headless_coding_agent_interactions, "_codex_remote", return_value="unix:///tmp/rc.sock"),
        mock.patch.object(
            headless_coding_agent_interactions.asyncio, "create_subprocess_exec", return_value=process
        ) as spawn,
    ):
        response = await client.post(
            "/lapdog/coding_agent/send",
            json={
                "coding_agent": agent,
                "session_id": "session",
                "message": message,
            },
        )
    assert response.status == (200 if exit_code == 0 else 502)
    assert await response.json() == {
        "coding_agent": agent,
        "session_id": "session",
        "exit_code": exit_code,
        "stdout": "output",
        "stderr": "error",
    }
    assert spawn.call_args.args == ("/bin/agent", *flags, message)
    assert spawn.call_args.kwargs["cwd"] == (None if binary_name == "codex" else str(tmp_path))
    which.assert_called_once_with(binary_name)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        None,
        {},
        {"coding_agent": "bash", "session_id": "s", "message": "m"},
        {"coding_agent": "claude", "session_id": "s", "message": "m"},
        {"coding_agent": "pi", "session_id": "s", "message": "m"},
        {"coding_agent": "pi-coding-agent", "session_id": 1, "message": "m"},
        {"coding_agent": "pi-coding-agent", "session_id": "s", "message": " "},
        {"coding_agent": "pi-coding-agent", "session_id": "s", "message": "a\0b"},
    ],
)
async def test_invalid_input(client, payload):
    with mock.patch.object(headless_coding_agent_interactions.asyncio, "create_subprocess_exec") as spawn:
        response = await client.post("/lapdog/coding_agent/send", json=payload)
    assert response.status == 400
    spawn.assert_not_called()


@pytest.mark.parametrize("agent,launcher", [("claude-code", "lapdog")])
async def test_missing_binary(client, agent, launcher):
    with mock.patch.object(headless_coding_agent_interactions.shutil, "which", return_value=None) as which:
        response = await client.post(
            "/lapdog/coding_agent/send",
            json={
                "coding_agent": agent,
                "session_id": "s",
                "message": "m",
            },
        )
    assert response.status == 503
    assert await response.text() == f"{launcher} was not found on the server PATH."
    which.assert_called_once_with(launcher)


async def test_timeout_kills_process(client):
    process = mock.Mock(returncode=None)
    process.communicate = mock.AsyncMock(side_effect=asyncio.TimeoutError)
    process.wait = mock.AsyncMock()
    with (
        mock.patch.object(headless_coding_agent_interactions.shutil, "which", return_value="/bin/lapdog"),
        mock.patch.object(headless_coding_agent_interactions.asyncio, "create_subprocess_exec", return_value=process),
    ):
        response = await client.post(
            "/lapdog/coding_agent/send",
            json={
                "coding_agent": "claude-code",
                "session_id": "s",
                "message": "m",
            },
        )
    assert response.status == 504
    process.kill.assert_called_once()
    process.wait.assert_awaited_once()


@pytest.mark.parametrize("agent", ["claude-code", "pi-coding-agent"])
async def test_running_process_prevents_headless_resume(client, monkeypatch, agent):
    monkeypatch.setattr(headless_coding_agent_interactions, "_process_may_be_running", lambda pid: True)
    with (
        mock.patch.object(headless_coding_agent_interactions.shutil, "which", return_value="/bin/lapdog"),
        mock.patch("asyncio.create_subprocess_exec") as spawn,
    ):
        response = await client.post(
            "/lapdog/coding_agent/send",
            json={"coding_agent": agent, "session_id": "session", "message": "hello"},
        )
    assert response.status == 409
    assert "may still be running" in await response.text()
    spawn.assert_not_called()


async def test_resume_requires_existing_working_directory(client, hooks_api):
    hooks_api._sessions["session"].cwd = ""
    with (
        mock.patch.object(headless_coding_agent_interactions.shutil, "which", return_value="/bin/lapdog"),
        mock.patch("asyncio.create_subprocess_exec") as spawn,
    ):
        response = await _send_pi(client, "session")
    assert response.status == 409
    assert "working directory" in await response.text()
    spawn.assert_not_called()


async def test_concurrent_resume_is_rejected_and_guard_is_released(client):
    started = asyncio.Event()
    finish = asyncio.Event()

    async def communicate():
        started.set()
        await finish.wait()
        return b"done", b""

    process = mock.Mock(returncode=0, communicate=communicate)
    with (
        mock.patch.object(headless_coding_agent_interactions.shutil, "which", return_value="/bin/lapdog"),
        mock.patch("asyncio.create_subprocess_exec", return_value=process) as spawn,
    ):
        first = asyncio.create_task(_send_pi(client, "session"))
        try:
            await asyncio.wait_for(started.wait(), timeout=1)
            second = await _send_pi(client, "session")
            assert second.status == 409
            spawn.assert_awaited_once()
        finally:
            finish.set()
            await first
        assert (await _send_pi(client, "session")).status == 200


@pytest.mark.parametrize("error,expected", [(None, True), (ProcessLookupError(), False), (PermissionError(), True)])
def test_process_check_only_accepts_confirmed_exit(error, expected):
    with mock.patch.object(headless_coding_agent_interactions.os, "kill", side_effect=error):
        assert headless_coding_agent_interactions._process_may_be_running(12345) is expected


@pytest.mark.parametrize(
    "agent,route,event,command",
    [
        ("claude-code", "/claude/hooks", "SessionStart", "claude"),
        ("pi-coding-agent", "/pi/hooks", "session_start", "pi"),
    ],
)
async def test_hook_process_metadata_enables_closed_session_resume(
    lapdog_agent, tmp_path, agent, route, event, command
):
    response = await lapdog_agent.post(
        route,
        json={
            "session_id": "closed-session",
            "hook_event_name": event,
            "lapdog_process_id": 12345,
            "cwd": str(tmp_path),
        },
    )
    assert response.status == 200
    process = mock.Mock(returncode=0, communicate=mock.AsyncMock(return_value=(b"done", b"")))
    with (
        mock.patch.object(headless_coding_agent_interactions.shutil, "which", return_value="/bin/lapdog"),
        mock.patch.object(headless_coding_agent_interactions, "_process_may_be_running", return_value=False),
        mock.patch("asyncio.create_subprocess_exec", return_value=process) as spawn,
    ):
        response = await lapdog_agent.post(
            "/lapdog/coding_agent/send",
            json={"coding_agent": agent, "session_id": "closed-session", "message": "continue"},
        )
    assert response.status == 200
    assert spawn.call_args.args[:2] == ("/bin/lapdog", command)
    assert spawn.call_args.kwargs["cwd"] == str(tmp_path)


def test_socket_discovery(tmp_path):
    path = tmp_path / "rc.sock"
    with socket.socket(socket.AF_UNIX) as listener:
        listener.bind(str(path))
        listener.listen()
        with mock.patch.object(headless_coding_agent_interactions.tempfile, "gettempdir", return_value=str(tmp_path)):
            assert headless_coding_agent_interactions._codex_remote() == "unix://" + str(path)
    path.unlink()


@pytest.mark.parametrize("custom_home", [False, True])
def test_standard_codex_socket(tmp_path, monkeypatch, custom_home):
    if custom_home:
        home = tmp_path / "custom"
        monkeypatch.setenv("CODEX_HOME", str(home))
    else:
        home = tmp_path / ".codex"
        monkeypatch.delenv("CODEX_HOME")
        monkeypatch.setattr(headless_coding_agent_interactions.Path, "home", lambda: tmp_path)
    path = home / "app-server-control" / "app-server-control.sock"
    path.parent.mkdir(parents=True)
    try:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
            listener.listen()
            with mock.patch.object(headless_coding_agent_interactions.os, "walk") as walk:
                assert headless_coding_agent_interactions._codex_remote() == "unix://" + str(path)
            walk.assert_not_called()
    finally:
        path.unlink(missing_ok=True)


def test_socket_discovery_skips_stale_socket(tmp_path):
    stale = tmp_path / "rc.sock"
    live_directory = tmp_path / "live"
    live_directory.mkdir()
    live = live_directory / "rc.sock"
    try:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(stale))
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(live))
            listener.listen()
            with mock.patch.object(
                headless_coding_agent_interactions.tempfile, "gettempdir", return_value=str(tmp_path)
            ):
                assert headless_coding_agent_interactions._codex_remote() == "unix://" + str(live)
    finally:
        stale.unlink(missing_ok=True)
        live.unlink(missing_ok=True)


def test_only_stale_socket_is_unavailable(tmp_path):
    path = tmp_path / "rc.sock"
    try:
        with socket.socket(socket.AF_UNIX) as listener:
            listener.bind(str(path))
        with mock.patch.object(
            headless_coding_agent_interactions.os, "walk", return_value=[(str(tmp_path), [], ["rc.sock"])]
        ):
            with pytest.raises(web.HTTPServiceUnavailable) as error:
                headless_coding_agent_interactions._codex_remote()
            assert "No reachable Codex" in error.value.text
    finally:
        path.unlink(missing_ok=True)


def test_socket_missing():
    with mock.patch.object(headless_coding_agent_interactions.os, "walk", return_value=[]):
        with pytest.raises(web.HTTPServiceUnavailable):
            headless_coding_agent_interactions._codex_remote()


def test_windows_codex():
    with mock.patch.object(headless_coding_agent_interactions.sys, "platform", "win32"):
        with pytest.raises(web.HTTPNotImplemented):
            headless_coding_agent_interactions._codex_remote()


async def _connect_pi(client, session_id="session-a", token="token-a"):
    socket = await client.ws_connect("/lapdog/pi/connect")
    await socket.send_json({"session_id": session_id, "token": token})
    return socket


async def _send_pi(client, session_id="session-a"):
    return await client.post(
        "/lapdog/coding_agent/send",
        json={"coding_agent": PI_CODING_AGENT_ML_APP, "session_id": session_id, "message": "hello\nworld"},
        headers={"Origin": "https://app.datadoghq.com"},
    )


async def test_live_delivery_routes_to_correct_session(client):
    first = await _connect_pi(client)
    second = await _connect_pi(client, "session-b", "token-b")
    assert await first.receive_json() == {"type": "ready"}
    assert await second.receive_json() == {"type": "ready"}
    with mock.patch("asyncio.create_subprocess_exec") as spawn:
        request = asyncio.create_task(_send_pi(client, "session-b"))
        message = await second.receive_json(timeout=1)
        assert message["content"] == "hello\nworld"
        assert message["type"] == "message"
        assert not request.done()
        await second.send_json({"type": "accepted", "message_id": message["message_id"]})
        response = await request
        spawn.assert_not_called()
    assert response.status == 202
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.datadoghq.com"
    assert await response.json() == {
        "coding_agent": PI_CODING_AGENT_ML_APP,
        "session_id": "session-b",
        "status": "accepted",
        "message_id": message["message_id"],
    }
    await first.close()
    await second.close()


async def test_disconnected_session_does_not_launch_headless_pi(client):
    with mock.patch("asyncio.create_subprocess_exec") as spawn:
        response = await _send_pi(client)
    assert response.status == 409
    assert response.headers["Access-Control-Allow-Origin"] == "https://app.datadoghq.com"
    spawn.assert_not_called()


@pytest.mark.parametrize("token", ["", "wrong", "token-b"])
async def test_connection_requires_session_launch_token(client, token):
    socket = await _connect_pi(client, token=token)
    assert (await socket.receive()).type == WSMsgType.CLOSE
    assert socket.close_code == 1008
    assert (await _send_pi(client)).status == 409


async def test_duplicate_connection_does_not_replace_original(client):
    first = await _connect_pi(client)
    await first.receive_json()
    duplicate = await _connect_pi(client)
    assert (await duplicate.receive()).type == WSMsgType.CLOSE
    request = asyncio.create_task(_send_pi(client))
    message = await first.receive_json(timeout=1)
    await first.send_json({"type": "accepted", "message_id": message["message_id"]})
    assert (await request).status == 202
    await first.close()


@pytest.mark.parametrize("outcome,status", [("error", 502), ("disconnect", 503), ("timeout", 504)])
async def test_delivery_failure(client, monkeypatch, outcome, status):
    if outcome == "timeout":
        monkeypatch.setattr("lapdog.headless_coding_agent_interactions.DELIVERY_TIMEOUT", 0.05)
    socket = await _connect_pi(client)
    await socket.receive_json()
    request = asyncio.create_task(_send_pi(client))
    message = await socket.receive_json(timeout=1)
    if outcome == "error":
        await socket.send_json({"type": "error", "message_id": message["message_id"]})
    elif outcome == "disconnect":
        await socket.close()
    response = await asyncio.wait_for(request, timeout=1)
    assert response.status == status
    if outcome == "timeout":
        # A late acknowledgement does not break the connection or resend work.
        await socket.send_json({"type": "accepted", "message_id": message["message_id"]})
        retry = asyncio.create_task(_send_pi(client))
        next_message = await socket.receive_json(timeout=1)
        assert next_message["message_id"] != message["message_id"]
        await socket.send_json({"type": "accepted", "message_id": next_message["message_id"]})
        assert (await retry).status == 202
    await socket.close()


async def test_pi_session_can_reconnect(client):
    first = await _connect_pi(client)
    await first.receive_json()
    await first.close()
    second = await _connect_pi(client)
    assert await second.receive_json() == {"type": "ready"}
    await second.close()


async def test_server_shutdown_closes_pi_connection(client):
    socket = await _connect_pi(client)
    await socket.receive_json()
    await client.app.shutdown()
    assert (await socket.receive()).type == WSMsgType.CLOSE


async def test_pi_hook_registers_live_connection(lapdog_agent):
    response = await lapdog_agent.post(
        "/pi/hooks",
        json={"hook_event_name": "session_start", "session_id": "session-a", "lapdog_session_token": "token-a"},
    )
    assert response.status == 200
    socket = await _connect_pi(lapdog_agent)
    assert await socket.receive_json() == {"type": "ready"}
    request = asyncio.create_task(_send_pi(lapdog_agent))
    message = await socket.receive_json(timeout=1)
    await socket.send_json({"type": "accepted", "message_id": message["message_id"]})
    assert (await request).status == 202
    await socket.close()
