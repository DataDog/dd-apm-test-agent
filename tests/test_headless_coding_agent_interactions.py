"""Tests for sending messages to local coding agents."""

import asyncio
import socket
from unittest import mock

import pytest
from aiohttp import web

from lapdog import headless_coding_agent_interactions


@pytest.fixture(autouse=True)
def isolated_codex_home(tmp_path, monkeypatch):
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))


@pytest.fixture
async def client(aiohttp_client):
    app = web.Application()
    api = headless_coding_agent_interactions.HeadlessCodingAgentInteractionsAPI()
    app.add_routes(api.get_routes())
    return await aiohttp_client(app)


@pytest.mark.parametrize(
    "agent,binary_name,flags",
    [
        ("codex", "codex", ["--remote", "unix:///tmp/rc.sock", "queue", "--thread", "session", "--message"]),
        ("claude-code", "lapdog", ["claude", "--resume", "session", "-p"]),
        ("pi-coding-agent", "pi", ["--session", "session", "--print"]),
    ],
)
@pytest.mark.parametrize("exit_code", [0, 1])
@pytest.mark.parametrize("custom_name", [False, True])
async def test_send(client, agent, binary_name, flags, exit_code, custom_name, monkeypatch):
    if custom_name:
        agent = f"custom-{agent}"
        if binary_name == "codex":
            monkeypatch.setenv("DD_CODEX_ML_APP", agent)
        else:
            setting = "CLAUDE_CODE_ML_APP" if binary_name == "lapdog" else "PI_CODING_AGENT_ML_APP"
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


@pytest.mark.parametrize("agent,launcher", [("pi-coding-agent", "pi"), ("claude-code", "lapdog")])
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
        mock.patch.object(headless_coding_agent_interactions.shutil, "which", return_value="/bin/pi"),
        mock.patch.object(headless_coding_agent_interactions.asyncio, "create_subprocess_exec", return_value=process),
    ):
        response = await client.post(
            "/lapdog/coding_agent/send",
            json={
                "coding_agent": "pi-coding-agent",
                "session_id": "s",
                "message": "m",
            },
        )
    assert response.status == 504
    process.kill.assert_called_once()
    process.wait.assert_awaited_once()


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
