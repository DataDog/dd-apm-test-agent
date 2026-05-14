from unittest import mock

from lapdog import cli


def test_codex_command_is_registered():
    assert "codex" in cli.LAPDOG_COMMANDS
    assert "codex" in cli.LAPDOG_USAGE


def test_cmd_codex_starts_watcher_and_execs_codex():
    with mock.patch("lapdog.cli._ensure_lapdog_running", return_value=8126) as ensure:
        with mock.patch("lapdog.cli._start_codex_watcher") as start_watcher:
            with mock.patch("lapdog.cli._run_codex") as run_codex:
                with mock.patch("lapdog.cli.uuid.uuid4", return_value=mock.Mock(hex="proxy-key")):
                    with mock.patch("lapdog.cli.build_running_banner", return_value="banner"):
                        cli.cmd_codex(["--model", "gpt-5.5"], forward_data=True)

    ensure.assert_called_once_with(True, detached=True)
    start_watcher.assert_called_once_with(8126, proxy_session_key="proxy-key")
    run_codex.assert_called_once_with(args=["--model", "gpt-5.5"], port=8126, proxy_session_key="proxy-key")


def test_start_codex_watcher_waits_for_ready_file(tmp_path, monkeypatch):
    ready_paths = []
    popen_args = []

    def fake_popen(args, **kwargs):
        popen_args.append(args)
        ready_path = args[args.index("--ready-file") + 1]
        ready_paths.append(ready_path)
        with open(ready_path, "w") as f:
            f.write("ready\n")
        process = mock.Mock()
        process.poll.return_value = None
        return process

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    cli._start_codex_watcher(8126, proxy_session_key="proxy-key")

    assert ready_paths
    assert "--proxy-session-key" in popen_args[0]
    assert popen_args[0][popen_args[0].index("--proxy-session-key") + 1] == "proxy-key"


def test_run_codex_injects_lapdog_provider(monkeypatch):
    exec_call = {}

    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/local/bin/codex")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")

    def fake_execve(binary, argv, env):
        exec_call["binary"] = binary
        exec_call["argv"] = argv
        exec_call["env"] = env
        raise SystemExit(0)

    monkeypatch.setattr(cli.os, "execve", fake_execve)

    try:
        cli._run_codex(args=["exec", "hello"], port=8126, proxy_session_key="proxy-key")
    except SystemExit:
        pass

    assert exec_call["binary"] == "/usr/local/bin/codex"
    assert exec_call["env"]["OPENAI_BASE_URL"] == "http://localhost:8126/codex/proxy/proxy-key/v1"
    assert exec_call["argv"][:5] == [
        "/usr/local/bin/codex",
        "-c",
        'model_provider="openai-lapdog"',
        "-c",
        (
            'model_providers.openai-lapdog={name="OpenAI via Lapdog",'
            ' base_url="http://localhost:8126/codex/proxy/proxy-key/v1", env_key="OPENAI_API_KEY",'
            ' wire_api="responses"}'
        ),
    ]
    assert exec_call["argv"][5:] == ["exec", "hello"]


def test_run_codex_falls_back_without_openai_api_key(monkeypatch):
    exec_call = {}

    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/local/bin/codex")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def fake_execve(binary, argv, env):
        exec_call["argv"] = argv
        exec_call["env"] = env
        raise SystemExit(0)

    monkeypatch.setattr(cli.os, "execve", fake_execve)

    try:
        cli._run_codex(args=["exec", "hello"], port=8126)
    except SystemExit:
        pass

    assert exec_call["env"]["OPENAI_BASE_URL"] == "http://localhost:8126/codex/proxy/v1"
    assert exec_call["argv"] == ["/usr/local/bin/codex", "exec", "hello"]
