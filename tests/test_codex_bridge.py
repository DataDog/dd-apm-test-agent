import io
import json
from pathlib import Path
import plistlib
from unittest import mock

import pytest

from lapdog import codex_bridge
from lapdog import codex_hook
from lapdog import codex_registration
from lapdog.cli import codex_desktop


@pytest.mark.parametrize("method", ["thread/start", "thread/resume", "thread/fork"])
def test_registry_uses_only_responses_to_own_requests(method, monkeypatch):
    send = mock.Mock()
    monkeypatch.setattr(codex_registration, "request", send)
    registry = codex_bridge.SessionRegistry("http://localhost:12345", "owner")

    def observe(message, outgoing=False):
        registry.observe(json.dumps(message).encode(), outgoing=outgoing)

    observe({"method": "thread/started", "params": {"thread": {"id": "unrelated"}}})
    observe({"id": 2, "result": {"thread": {"id": "unrelated"}}})
    observe({"id": 1, "method": method}, outgoing=True)
    observe({"id": 1, "result": {"thread": {"id": "own"}}})
    assert registry.sessions == {"own"}
    send.assert_called_once_with(registry.url, {"owner": "owner", "session_ids": ["own"]})
    observe({"method": "thread/started", "params": {"thread": {"id": "foreign-child", "parentThreadId": "plain"}}})
    assert registry.sessions == {"own"}
    observe({"method": "thread/started", "params": {"thread": {"id": "child", "parentThreadId": "own"}}})
    assert registry.sessions == {"own", "child"}
    observe({"id": 3, "method": method}, outgoing=True)
    observe({"id": 3, "error": {"message": "failed"}})
    assert not registry.pending
    registry.refresh(close=True)
    assert send.call_args.args[1] == {"owner": "owner", "session_ids": []}


def test_unregistered_hook_does_not_read_transcripts_or_names(monkeypatch):
    send = mock.Mock(return_value={"registered": False})
    monkeypatch.setattr(codex_hook, "request", send)
    with mock.patch.object(codex_hook, "send_transcript") as transcript, mock.patch.object(
        codex_hook, "read_session_names"
    ) as names:
        codex_hook.forward(
            "http://localhost:12345",
            {"session_id": "plain", "hook_event_name": "PostToolUse", "transcript_path": "/private/session.jsonl"},
        )
    transcript.assert_not_called()
    names.assert_not_called()
    assert send.call_count == 1


def test_cached_global_hook_is_inert(monkeypatch, capsys):
    monkeypatch.setattr(codex_hook.sys, "argv", ["hook", "--url", "http://localhost:12345"])
    with mock.patch.object(codex_hook, "forward") as forward:
        codex_hook.main()
    forward.assert_not_called()
    assert capsys.readouterr().out == "{}\n"


async def test_registration_expiry_children_and_collector_gate(lapdog_agent, monkeypatch):
    from lapdog import codex_lifecycle

    now = [100.0]
    monkeypatch.setattr(codex_lifecycle.time, "monotonic", lambda: now[0])
    path = "/codex/hooks/registrations"
    assert (await (await lapdog_agent.get(path + "?session_id=parent")).json()) == {"registered": False}
    body = {"session_id": "parent", "capture_session_id": "parent", "records": []}
    assert (await lapdog_agent.post("/codex/hooks/native", json=body)).status == 403
    assert (await lapdog_agent.post(path, json={"owner": "owner", "session_ids": ["parent"]})).status == 200
    assert (await lapdog_agent.post(path, json={"parent_session_id": "plain", "session_ids": ["bad"]})).status == 400
    assert (await lapdog_agent.post(path, json={"parent_session_id": "parent", "session_ids": ["child"]})).status == 200
    assert (await lapdog_agent.post("/codex/hooks/native", json=body)).status == 200
    now[0] += 30
    await lapdog_agent.post(path, json={"owner": "owner", "session_ids": ["parent"]})
    assert (await (await lapdog_agent.get(path + "?session_id=child")).json())["registered"]
    now[0] += 61
    assert not (await (await lapdog_agent.get(path + "?session_id=child")).json())["registered"]
    assert (await lapdog_agent.post("/codex/hooks/native", json=body)).status == 403
    await lapdog_agent.post(path, json={"owner": "owner", "session_ids": ["parent"]})
    await lapdog_agent.post(path, json={"owner": "owner", "session_ids": []})
    assert not (await (await lapdog_agent.get(path + "?session_id=parent")).json())["registered"]


@pytest.mark.parametrize("running", [False, True])
def test_desktop_launch_attaches_wrapper_only_to_fresh_app(tmp_path, monkeypatch, running):
    monkeypatch.setattr(codex_desktop.sys, "platform", "darwin")
    paths = mock.Mock(side_effect=lambda value: tmp_path / "Applications" if value == "/Applications" else Path(value))
    paths.home.return_value = tmp_path
    monkeypatch.setattr(codex_desktop, "Path", paths)
    monkeypatch.setattr(codex_desktop, "LAPDOG_DIR", str(tmp_path / "lapdog"))
    bundle = tmp_path / "Applications/Codex.app"
    (bundle / "Contents/Resources").mkdir(parents=True)
    (bundle / "Contents/Info.plist").write_bytes(
        plistlib.dumps({"CFBundleIdentifier": "com.openai.codex", "CFBundleExecutable": "Codex"})
    )
    executable = str(bundle / "Contents/MacOS/Codex")
    run = mock.Mock(return_value=mock.Mock(stdout=executable + "\n" if running else ""))
    monkeypatch.setattr(codex_desktop.subprocess, "run", run)
    monkeypatch.setattr(codex_desktop.codex_setup, "supported", lambda _: True)
    with mock.patch.object(codex_desktop.codex_setup, "configure") as configure:
        if running:
            with pytest.raises(RuntimeError, match="Quit Codex desktop"):
                codex_desktop.launch("/repo", 12345, "owner")
            configure.assert_not_called()
            assert run.call_count == 1
            return
        codex_desktop.launch("/repo", 12345, "owner")
    argv = run.call_args.args[0]
    assert "CODEX_APP_SERVER_FORCE_CLI=1" in argv
    wrapper = tmp_path / "lapdog/codex-desktop-backend"
    assert f"CODEX_CLI_PATH={wrapper}" in argv
    assert "lapdog.codex_bridge" in wrapper.read_text()
    assert "--owner owner" in wrapper.read_text()


@pytest.mark.parametrize("marker", [None, "", "isolated"])
def test_global_hook_selects_capture_scope(monkeypatch, marker):
    # Legacy variables from an old daemon must never authorize capture.
    monkeypatch.setenv("LAPDOG_SESSION_TOKEN", "stale-token")
    monkeypatch.setenv("LAPDOG_URL", "http://localhost:8126")
    monkeypatch.delenv("LAPDOG_CODEX_CAPTURE", raising=False)
    if marker is not None:
        monkeypatch.setenv("LAPDOG_CODEX_CAPTURE", marker)
    monkeypatch.setattr(codex_hook.sys, "argv", ["hook", "--url", "http://localhost:12345", "--capture"])
    payload = {"session_id": "session", "hook_event_name": "SessionStart"}
    monkeypatch.setattr(codex_hook.sys, "stdin", io.StringIO(json.dumps(payload)))
    with mock.patch.object(codex_hook, "forward") as forward:
        codex_hook.main()
    forward.assert_called_once_with("http://localhost:12345", payload)
