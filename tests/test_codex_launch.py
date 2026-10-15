import json
from pathlib import Path
from unittest import mock

import pytest

from lapdog import codex_launch
from lapdog import codex_registration


def write_records(path, records):
    path.write_text("".join(json.dumps(record) + "\n" for record in records))


def test_terminal_match_requires_current_prompt_identity(tmp_path):
    log = tmp_path / "terminal.jsonl"
    transcript = tmp_path / "rollout.jsonl"
    write_records(log, [{"payload": {"UserTurn": {"client_user_message_id": "own-prompt"}}}])
    write_records(
        transcript,
        [
            {"type": "session_meta", "payload": {"id": "session"}},
            {
                "type": "event_msg",
                "payload": {
                    "type": "item_completed",
                    "turn_id": "old",
                    "item": {"type": "UserMessage", "client_id": "own-prompt"},
                },
            },
            {
                "type": "event_msg",
                "payload": {
                    "type": "item_completed",
                    "turn_id": "current",
                    "item": {"type": "UserMessage", "client_id": "plain-prompt"},
                },
            },
        ],
    )
    assert codex_launch.matches_terminal(str(log), str(transcript), "old", "session")
    assert not codex_launch.matches_terminal(str(log), str(transcript), "current", "session")
    assert not codex_launch.matches_terminal(str(log), str(transcript), "old", "other-session")
    log.write_text('{"payload":')
    assert not codex_launch.matches_terminal(str(log), str(transcript), "old", "session")


def test_process_ownership_excludes_shared_daemon(monkeypatch):
    if codex_launch.os.name == "nt":
        pytest.skip("POSIX process table fixture")
    table = (
        "10 1 codex\n20 10 sh -c hook\n30 20 python hook\n40 10 codex app-server --managed-daemon\n50 40 python hook\n"
    )
    monkeypatch.setattr(codex_launch.subprocess, "run", mock.Mock(return_value=mock.Mock(stdout=table)))
    assert codex_launch.owns_process(10, 30)
    assert not codex_launch.owns_process(10, 50)
    assert not codex_launch.owns_process(99, 30)


@pytest.mark.parametrize("platform,binary,shell", [("darwin", "codex", False), ("win32", "codex.cmd", True)])
def test_launcher_preserves_arguments_and_cleans_registration(monkeypatch, platform, binary, shell):
    child = mock.Mock(pid=123, wait=mock.Mock(return_value=0))
    spawn = mock.Mock(return_value=child)
    send = mock.Mock()
    monkeypatch.setattr(codex_launch.subprocess, "Popen", spawn)
    monkeypatch.setattr(codex_registration, "request", send)
    monkeypatch.setattr(codex_launch.sys, "platform", platform)
    argv = [binary, "resume", "--last"]
    with pytest.raises(SystemExit) as stopped:
        codex_launch.run(argv, {}, 12345, "owner")
    assert stopped.value.code == 0
    assert spawn.call_args.args[0] == argv
    assert spawn.call_args.kwargs["shell"] is shell
    path = spawn.call_args.kwargs["env"]["CODEX_TUI_SESSION_LOG_PATH"]
    assert not Path(path).parent.exists()
    assert send.call_args_list[0].args[1] == {"owner": "owner", "session_ids": [], "pid": 123, "log_path": path}
    assert send.call_args_list[-1].args[1] == {"owner": "owner", "session_ids": []}


async def test_terminal_registration_expires_and_does_not_capture_plain_resume(lapdog_agent, tmp_path, monkeypatch):
    log = tmp_path / "terminal.jsonl"
    transcript = tmp_path / "rollout.jsonl"
    write_records(log, [{"payload": {"UserTurn": {"client_user_message_id": "own"}}}])
    write_records(
        transcript,
        [
            {"type": "session_meta", "payload": {"id": "session"}},
            {
                "type": "event_msg",
                "payload": {
                    "type": "item_completed",
                    "turn_id": "turn",
                    "item": {"type": "UserMessage", "client_id": "own"},
                },
            },
        ],
    )
    monkeypatch.setattr(codex_launch, "owns_process", lambda *_: False)
    url = "/codex/hooks/registrations"
    await lapdog_agent.post(url, json={"owner": "owner", "session_ids": [], "pid": 123, "log_path": str(log)})
    query = {"session_id": "session", "pid": "456", "path": str(transcript), "turn_id": "turn"}
    assert (await (await lapdog_agent.get(url, params=query)).json())["registered"]
    await lapdog_agent.post(url, json={"owner": "owner", "session_ids": []})
    assert not (await (await lapdog_agent.get(url, params=query)).json())["registered"]
    # A new launcher cannot authorize an old transcript marker from a prior launch.
    write_records(log, [{"payload": {"UserTurn": {"client_user_message_id": "new"}}}])
    await lapdog_agent.post(url, json={"owner": "new-owner", "session_ids": [], "pid": 123, "log_path": str(log)})
    assert not (await (await lapdog_agent.get(url, params=query)).json())["registered"]


def test_registration_cleanup_on_error_prevents_late_renewal(monkeypatch):
    send = mock.Mock()
    monkeypatch.setattr(codex_registration, "request", send)
    registry = codex_registration.RegistrationClient("http://localhost:12345", "owner")
    registry.sessions.add("session")
    with pytest.raises(RuntimeError, match="disconnected"):
        with registry.keepalive():
            raise RuntimeError("disconnected")
    assert send.call_args_list[0].args[1]["session_ids"] == ["session"]
    assert send.call_args_list[-1].args[1]["session_ids"] == []
    count = send.call_count
    registry.refresh()
    assert send.call_count == count
