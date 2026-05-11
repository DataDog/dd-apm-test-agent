from unittest import mock

from lapdog import cli


def test_codex_command_is_registered():
    assert "codex" in cli.LAPDOG_COMMANDS
    assert "codex" in cli.LAPDOG_USAGE


def test_cmd_codex_starts_watcher_and_execs_codex():
    with mock.patch("lapdog.cli._ensure_lapdog_running", return_value=8126) as ensure:
        with mock.patch("lapdog.cli._start_codex_watcher") as start_watcher:
            with mock.patch("lapdog.cli._run_codex") as run_codex:
                with mock.patch("lapdog.cli.build_running_banner", return_value="banner"):
                    cli.cmd_codex(["--model", "gpt-5.5"], forward_data=True)

    ensure.assert_called_once_with(True, detached=True)
    start_watcher.assert_called_once_with(8126)
    run_codex.assert_called_once_with(args=["--model", "gpt-5.5"])


def test_start_codex_watcher_waits_for_ready_file(tmp_path, monkeypatch):
    ready_paths = []

    def fake_popen(args, **kwargs):
        ready_path = args[args.index("--ready-file") + 1]
        ready_paths.append(ready_path)
        with open(ready_path, "w") as f:
            f.write("ready\n")
        process = mock.Mock()
        process.poll.return_value = None
        return process

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    cli._start_codex_watcher(8126)

    assert ready_paths
