import json
import subprocess
from unittest import mock

from lapdog import codex_args
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
    start_watcher.assert_called_once_with(
        8126,
        proxy_session_key="proxy-key",
        cwd=cli.os.getcwd(),
        parent_pid=cli.os.getpid(),
        singleton_key=None,
        include_all_cwds=False,
    )
    run_codex.assert_called_once_with(args=["--model", "gpt-5.5"], port=8126, proxy_session_key="proxy-key")


def test_cmd_codex_starts_watcher_with_forwarded_cd(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    target_cwd = tmp_path / "target"
    monkeypatch.setattr(cli.os, "getcwd", lambda: str(wrapper_cwd))

    with mock.patch("lapdog.cli._ensure_lapdog_running", return_value=8126):
        with mock.patch("lapdog.cli._start_codex_watcher") as start_watcher:
            with mock.patch("lapdog.cli._run_codex"):
                with mock.patch("lapdog.cli.uuid.uuid4", return_value=mock.Mock(hex="proxy-key")):
                    with mock.patch("lapdog.cli.build_running_banner", return_value="banner"):
                        cli.cmd_codex(["--cd", str(target_cwd), "--model", "gpt-5.5"], forward_data=True)

    start_watcher.assert_called_once_with(
        8126,
        proxy_session_key="proxy-key",
        cwd=str(target_cwd),
        parent_pid=cli.os.getpid(),
        singleton_key=None,
        include_all_cwds=False,
    )


def test_cmd_codex_app_starts_watcher_with_app_path_and_lapdog_pid(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    target_cwd = tmp_path / "target"
    monkeypatch.setattr(cli.os, "getcwd", lambda: str(wrapper_cwd))

    with mock.patch("lapdog.cli._ensure_lapdog_running", return_value=8126):
        with mock.patch("lapdog.cli._read_pid_file", return_value=(4242, 8126)):
            with mock.patch("lapdog.cli._stop_legacy_codex_app_watchers") as stop_legacy:
                with mock.patch("lapdog.cli._start_codex_watcher") as start_watcher:
                    with mock.patch("lapdog.cli._run_codex") as run_codex:
                        with mock.patch("lapdog.cli.build_running_banner", return_value="banner"):
                            cli.cmd_codex(["app", str(target_cwd)], forward_data=True)

    stop_legacy.assert_called_once_with(8126, 4242, codex_args.app_watcher_key(8126))
    start_watcher.assert_called_once_with(
        8126,
        proxy_session_key=None,
        cwd=str(target_cwd),
        parent_pid=4242,
        singleton_key=codex_args.app_watcher_key(8126),
        include_all_cwds=True,
    )
    run_codex.assert_called_once_with(args=["app", str(target_cwd)], port=8126, proxy_session_key=None)


def test_resolve_codex_cwd_handles_relative_cd(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    assert codex_args.resolve_cwd(["-C", "repo"]) == str(wrapper_cwd / "repo")


def test_resolve_codex_cwd_handles_equals_form(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    target_cwd = tmp_path / "target"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    assert codex_args.resolve_cwd([f"--cd={target_cwd}"]) == str(target_cwd)


def test_resolve_codex_cwd_ignores_args_after_double_dash(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    assert codex_args.resolve_cwd(["--", "--cd", str(tmp_path / "ignored")]) == str(wrapper_cwd)


def test_resolve_codex_cwd_handles_app_path(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    target_cwd = tmp_path / "target"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    assert codex_args.resolve_cwd(["app", str(target_cwd)]) == str(target_cwd)


def test_resolve_codex_cwd_handles_relative_app_path(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    assert codex_args.resolve_cwd(["app", "repo"]) == str(wrapper_cwd / "repo")


def test_resolve_codex_cwd_handles_app_options(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    target_cwd = tmp_path / "target"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    assert codex_args.resolve_cwd(
        ["-c", 'model="gpt-5.5"', "app", "--download-url", "https://example.com", str(target_cwd)]
    ) == str(target_cwd)


def test_resolve_codex_cwd_handles_app_add_dir_option(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    extra_cwd = tmp_path / "extra"
    target_cwd = tmp_path / "target"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    args = ["--add-dir", str(extra_cwd), "app", str(target_cwd)]

    assert codex_args.is_app_command(args)
    assert codex_args.resolve_cwd(args) == str(target_cwd)


def test_resolve_codex_cwd_does_not_treat_image_arguments_as_app_command(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    image_cwd = tmp_path / "image"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    args = ["-i", str(image_cwd), "app", "/another/image/path", "explain these images"]

    assert not codex_args.is_app_command(args)
    assert codex_args.resolve_cwd(args) == str(wrapper_cwd)


def test_resolve_codex_cwd_handles_app_default_with_cd(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    target_cwd = tmp_path / "target"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    assert codex_args.resolve_cwd(["--cd", str(target_cwd), "app"]) == str(target_cwd)


def test_resolve_codex_cwd_handles_relative_app_path_with_cd(monkeypatch, tmp_path):
    wrapper_cwd = tmp_path / "wrapper"
    target_cwd = tmp_path / "target"
    monkeypatch.setattr(codex_args.os, "getcwd", lambda: str(wrapper_cwd))

    assert codex_args.resolve_cwd(["--cd", str(target_cwd), "app", "repo"]) == str(target_cwd / "repo")


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

    cli._start_codex_watcher(8126, proxy_session_key="proxy-key", cwd=str(tmp_path))

    assert ready_paths
    assert "--proxy-session-key" in popen_args[0]
    assert popen_args[0][popen_args[0].index("--proxy-session-key") + 1] == "proxy-key"
    assert popen_args[0][popen_args[0].index("--cwd") + 1] == str(tmp_path)


def test_start_codex_watcher_uses_parent_pid(tmp_path, monkeypatch):
    popen_args = []

    def fake_popen(args, **kwargs):
        popen_args.append(args)
        ready_path = args[args.index("--ready-file") + 1]
        with open(ready_path, "w") as f:
            f.write("ready\n")
        process = mock.Mock()
        process.poll.return_value = None
        return process

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    cli._start_codex_watcher(8126, cwd=str(tmp_path), parent_pid=4242)

    assert popen_args[0][popen_args[0].index("--parent-pid") + 1] == "4242"


def test_start_codex_watcher_can_include_all_cwds(tmp_path, monkeypatch):
    popen_args = []

    def fake_popen(args, **kwargs):
        popen_args.append(args)
        ready_path = args[args.index("--ready-file") + 1]
        with open(ready_path, "w") as f:
            f.write("ready\n")
        process = mock.Mock()
        process.poll.return_value = None
        return process

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    cli._start_codex_watcher(8126, cwd=str(tmp_path), include_all_cwds=True)

    assert "--include-all-cwds" in popen_args[0]
    assert popen_args[0][popen_args[0].index("--cursor-path") + 1] == cli.CODEX_APP_CURSOR_FILE


def test_start_codex_watcher_skips_live_singleton(tmp_path, monkeypatch):
    pid_path = tmp_path / "codex-watcher-app-key.pid"
    pid_path.write_text("4242\n")
    reusable_calls = []

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(
        cli,
        "_codex_watcher_reusable",
        lambda pid, parent_pid, **kwargs: reusable_calls.append((pid, parent_pid, kwargs)) or pid == 4242,
    )
    popen = mock.Mock()
    monkeypatch.setattr(cli.subprocess, "Popen", popen)

    cli._start_codex_watcher(8126, cwd=str(tmp_path), singleton_key="app-key", include_all_cwds=True)

    popen.assert_not_called()
    assert reusable_calls == [
        (4242, cli.os.getpid(), {"lapdog_url": "http://localhost:8126", "include_all_cwds": True})
    ]


def test_start_codex_watcher_replaces_stale_singleton_parent(tmp_path, monkeypatch):
    pid_path = tmp_path / "codex-watcher-app-key.pid"
    pid_path.write_text("4242\n")
    popen_args = []

    def fake_popen(args, **kwargs):
        popen_args.append(args)
        ready_path = args[args.index("--ready-file") + 1]
        with open(ready_path, "w") as f:
            f.write("ready\n")
        process = mock.Mock()
        process.pid = 4343
        process.poll.return_value = None
        return process

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli, "_codex_watcher_reusable", lambda pid, parent_pid, **kwargs: False)
    monkeypatch.setattr(cli, "_codex_watcher_matches", lambda pid, **kwargs: False)
    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    cli._start_codex_watcher(8126, cwd=str(tmp_path), parent_pid=5252, singleton_key="app-key")

    assert popen_args
    assert popen_args[0][popen_args[0].index("--parent-pid") + 1] == "5252"
    assert pid_path.read_text() == "4343\n"


def test_start_codex_watcher_terminates_verified_stale_singleton(tmp_path, monkeypatch):
    pid_path = tmp_path / "codex-watcher-app-key.pid"
    pid_path.write_text("4242\n")
    kills = []

    def fake_popen(args, **kwargs):
        ready_path = args[args.index("--ready-file") + 1]
        with open(ready_path, "w") as f:
            f.write("ready\n")
        process = mock.Mock()
        process.pid = 4343
        process.poll.return_value = None
        return process

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli, "_codex_watcher_reusable", lambda pid, parent_pid, **kwargs: False)
    monkeypatch.setattr(cli, "_codex_watcher_matches", lambda pid, **kwargs: pid == 4242)
    monkeypatch.setattr(cli.os, "kill", lambda pid, sig: kills.append((pid, sig)))
    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    cli._start_codex_watcher(8126, cwd=str(tmp_path), parent_pid=5252, singleton_key="app-key")

    assert kills == [(4242, cli.signal.SIGTERM)]
    assert pid_path.read_text() == "4343\n"


def test_codex_watcher_reusable_requires_current_parent(monkeypatch):
    def fake_run(args, **kwargs):
        result = mock.Mock()
        result.returncode = 0
        result.stdout = (
            "python -m lapdog.codex_watcher --lapdog-url http://localhost:8126 " "--parent-pid 1111 --cwd /repo"
        )
        return result

    monkeypatch.setattr(cli, "_process_exists", lambda pid: pid == 4242)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli._codex_watcher_reusable(
        4242,
        1111,
        lapdog_url="http://localhost:8126",
        include_all_cwds=False,
    )
    assert not cli._codex_watcher_reusable(4242, 2222)
    assert not cli._codex_watcher_reusable(4242, 1111, lapdog_url="http://localhost:8127")
    assert not cli._codex_watcher_reusable(4242, 1111, include_all_cwds=True)


def test_codex_watcher_reusable_checks_windows_command(monkeypatch):
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        result = mock.Mock()
        result.returncode = 0
        result.stdout = (
            "python -m lapdog.codex_watcher --lapdog-url http://localhost:8126 "
            "--parent-pid 1111 --include-all-cwds --cwd C:\\repo"
        )
        return result

    monkeypatch.setattr(cli.os, "name", "nt")
    monkeypatch.setattr(cli, "_process_exists", lambda pid: pid == 4242)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert cli._codex_watcher_reusable(
        4242,
        1111,
        lapdog_url="http://localhost:8126",
        include_all_cwds=True,
    )
    assert calls[0][:3] == ["powershell", "-NoProfile", "-Command"]


def test_codex_watcher_reusable_rejects_unverified_command(monkeypatch):
    def fake_run(args, **kwargs):
        result = mock.Mock()
        result.returncode = 1
        result.stdout = ""
        return result

    monkeypatch.setattr(cli, "_process_exists", lambda pid: pid == 4242)
    monkeypatch.setattr(cli.subprocess, "run", fake_run)

    assert not cli._codex_watcher_reusable(4242, 1111)


def test_stop_codex_watcher_singleton_terminates_matching_watcher(tmp_path, monkeypatch):
    pid_path = tmp_path / "codex-watcher-legacy-key.pid"
    pid_path.write_text("4242\n")
    kills = []

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli, "_process_exists", lambda pid: pid == 4242)
    monkeypatch.setattr(
        cli,
        "_codex_watcher_reusable",
        lambda pid, parent_pid, **kwargs: pid == 4242 and parent_pid == 5252,
    )
    monkeypatch.setattr(cli.os, "kill", lambda pid, sig: kills.append((pid, sig)))

    cli._stop_codex_watcher_singleton("legacy-key", 5252)

    assert kills == [(4242, cli.signal.SIGTERM)]
    assert not pid_path.exists()


def test_stop_codex_watcher_singleton_ignores_nonmatching_process(tmp_path, monkeypatch):
    pid_path = tmp_path / "codex-watcher-legacy-key.pid"
    pid_path.write_text("4242\n")
    kill = mock.Mock()

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli, "_process_exists", lambda pid: pid == 4242)
    monkeypatch.setattr(cli, "_codex_watcher_reusable", lambda pid, parent_pid, **kwargs: False)
    monkeypatch.setattr(cli.os, "kill", kill)

    cli._stop_codex_watcher_singleton("legacy-key", 5252)

    kill.assert_not_called()
    assert pid_path.exists()


def test_stop_codex_watcher_singleton_removes_dead_pid_file(tmp_path, monkeypatch):
    pid_path = tmp_path / "codex-watcher-legacy-key.pid"
    pid_path.write_text("4242\n")
    kill = mock.Mock()

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli, "_process_exists", lambda pid: False)
    monkeypatch.setattr(cli.os, "kill", kill)

    cli._stop_codex_watcher_singleton("legacy-key", 5252)

    kill.assert_not_called()
    assert not pid_path.exists()


def test_stop_all_codex_watchers_terminates_all_watcher_pid_files(tmp_path, monkeypatch):
    (tmp_path / "codex-watcher-key-a.pid").write_text("1111\n")
    (tmp_path / "codex-watcher-key-b.pid").write_text("2222\n")
    (tmp_path / "lapdog.pid").write_text("3333\n")  # should be ignored
    kills = []

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli, "_codex_watcher_matches", lambda pid, **kwargs: True)
    monkeypatch.setattr(cli.os, "kill", lambda pid, sig: kills.append((pid, sig)))

    cli._stop_all_codex_watchers()

    assert sorted(kills) == [(1111, cli.signal.SIGTERM), (2222, cli.signal.SIGTERM)]
    assert not (tmp_path / "codex-watcher-key-a.pid").exists()
    assert not (tmp_path / "codex-watcher-key-b.pid").exists()


def test_stop_all_codex_watchers_removes_stale_pid_files(tmp_path, monkeypatch):
    pid_path = tmp_path / "codex-watcher-stale.pid"
    pid_path.write_text("9999\n")
    kill = mock.Mock()

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli, "_codex_watcher_matches", lambda pid, **kwargs: False)
    monkeypatch.setattr(cli.os, "kill", kill)

    cli._stop_all_codex_watchers()

    kill.assert_not_called()
    assert not pid_path.exists()


def test_stop_legacy_codex_app_watchers_skips_all_cwd_singleton(tmp_path, monkeypatch):
    keep_key = codex_args.app_watcher_key(8126)
    (tmp_path / f"codex-watcher-{keep_key}.pid").write_text("1111\n")
    (tmp_path / "codex-watcher-legacy-a.pid").write_text("2222\n")
    (tmp_path / "codex-watcher-legacy-b.pid").write_text("3333\n")
    (tmp_path / "other.pid").write_text("4444\n")
    stopped = []

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(
        cli,
        "_stop_codex_watcher_singleton",
        lambda singleton_key, parent_pid, **kwargs: stopped.append((singleton_key, parent_pid, kwargs)),
    )

    cli._stop_legacy_codex_app_watchers(8126, 5252, keep_key)

    assert sorted(stopped) == [
        ("legacy-a", 5252, {"lapdog_url": "http://localhost:8126", "include_all_cwds": False}),
        ("legacy-b", 5252, {"lapdog_url": "http://localhost:8126", "include_all_cwds": False}),
    ]


def test_start_codex_watcher_writes_singleton_pid(tmp_path, monkeypatch):
    def fake_popen(args, **kwargs):
        ready_path = args[args.index("--ready-file") + 1]
        with open(ready_path, "w") as f:
            f.write("ready\n")
        process = mock.Mock()
        process.pid = 4343
        process.poll.return_value = None
        return process

    monkeypatch.setattr(cli, "_log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)

    cli._start_codex_watcher(8126, cwd=str(tmp_path), singleton_key="app-key")

    assert (tmp_path / "codex-watcher-app-key.pid").read_text() == "4343\n"


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


def _write_installed_plugins(home, plugins):
    plugins_dir = home / ".claude" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    (plugins_dir / "installed_plugins.json").write_text(json.dumps({"version": 2, "plugins": plugins}))


def test_lapdog_plugin_installed_detects_marker(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: tmp_path))
    _write_installed_plugins(tmp_path, {cli.LAPDOG_PLUGIN_NAME: [{"scope": "user"}]})
    assert cli._lapdog_claude_code_plugin_installed() is True


def test_lapdog_plugin_installed_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: tmp_path))
    assert cli._lapdog_claude_code_plugin_installed() is False


def test_lapdog_plugin_installed_missing_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(cli.Path, "home", classmethod(lambda cls: tmp_path))
    _write_installed_plugins(tmp_path, {"other@market": [{"scope": "user"}]})
    assert cli._lapdog_claude_code_plugin_installed() is False


def test_ensure_lapdog_claude_code_plugin_installed_noop_when_present(monkeypatch):
    monkeypatch.setattr(cli, "_lapdog_claude_code_plugin_installed", lambda: True)
    with mock.patch("lapdog.cli.subprocess.run") as run:
        cli._ensure_lapdog_claude_code_plugin_installed()
    run.assert_not_called()


def test_ensure_lapdog_claude_code_plugin_installed_runs_both_commands(monkeypatch):
    monkeypatch.setattr(cli, "_lapdog_claude_code_plugin_installed", lambda: False)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/local/bin/claude")
    with mock.patch("lapdog.cli.subprocess.run") as run:
        cli._ensure_lapdog_claude_code_plugin_installed()
    assert run.call_count == 2
    args0 = run.call_args_list[0].args[0]
    args1 = run.call_args_list[1].args[0]
    assert args0 == ["/usr/local/bin/claude", "plugin", "marketplace", "add", cli.LAPDOG_MARKETPLACE_SOURCE]
    assert args1 == ["/usr/local/bin/claude", "plugin", "install", cli.LAPDOG_PLUGIN_NAME]


def test_ensure_lapdog_claude_code_plugin_installed_skips_without_claude_binary(monkeypatch):
    monkeypatch.setattr(cli, "_lapdog_claude_code_plugin_installed", lambda: False)
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    with mock.patch("lapdog.cli.subprocess.run") as run:
        cli._ensure_lapdog_claude_code_plugin_installed()
    run.assert_not_called()


def test_ensure_lapdog_claude_code_plugin_installed_continues_on_failure(monkeypatch, capsys):
    monkeypatch.setattr(cli, "_lapdog_claude_code_plugin_installed", lambda: False)
    monkeypatch.setattr(cli.shutil, "which", lambda name: "/usr/local/bin/claude")

    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=cmd, stderr="boom")

    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    cli._ensure_lapdog_claude_code_plugin_installed()  # must not raise
    err = capsys.readouterr().err
    assert "failed" in err
    assert "claude plugin install lapdog@lapdog" in err


def test_cmd_claude_auto_installs_plugin_by_default():
    with mock.patch("lapdog.cli._ensure_lapdog_claude_code_plugin_installed") as install:
        with mock.patch("lapdog.cli._ensure_lapdog_running", return_value=8126):
            with mock.patch("lapdog.cli.build_running_banner", return_value="banner"):
                with mock.patch("lapdog.cli._run_claude") as run_claude:
                    cli.cmd_claude(["--model", "opus"], forward_data=False, install_plugin=True)
    install.assert_called_once_with()
    run_claude.assert_called_once_with(["--model", "opus"])


def test_cmd_claude_skips_plugin_install_when_opted_out():
    with mock.patch("lapdog.cli._ensure_lapdog_claude_code_plugin_installed") as install:
        with mock.patch("lapdog.cli._ensure_lapdog_running", return_value=8126):
            with mock.patch("lapdog.cli.build_running_banner", return_value="banner"):
                with mock.patch("lapdog.cli._run_claude"):
                    cli.cmd_claude([], forward_data=False, install_plugin=False)
    install.assert_not_called()


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


def test_backfill_flag_parses():
    parsed = cli._parse_lapdog_args(["--backfill"])
    assert parsed.backfill is True
    assert parsed.forward is False


def test_subcommand_args_are_not_reparsed_as_lapdog_args():
    lapdog_args, remaining = cli._parse_command(["claude", "--backfill"])

    assert lapdog_args == []
    assert remaining == ["claude", "--backfill"]


def test_command_local_backfill_is_consumed():
    args, backfill = cli._consume_backfill_arg(["--model", "opus", "--backfill"])

    assert args == ["--model", "opus"]
    assert backfill is True


def test_command_local_backfill_after_double_dash_is_forwarded():
    args, backfill = cli._consume_backfill_arg(["--", "--backfill"])

    assert args == ["--", "--backfill"]
    assert backfill is False


def test_cmd_claude_backfill_does_not_exec_claude():
    with mock.patch("lapdog.cli._ensure_lapdog_running", return_value=8126) as ensure:
        with mock.patch("lapdog.cli._run_claude") as run_claude:
            with mock.patch("lapdog.cli._ensure_lapdog_claude_code_plugin_installed") as install:
                with mock.patch("lapdog.backfill_claude.backfill") as run_backfill:
                    cli.cmd_claude([], forward_data=True, install_plugin=True, backfill=True)

    ensure.assert_called_once_with(forward_data=False, detached=True)
    run_backfill.assert_called_once_with("http://localhost:8126")
    run_claude.assert_not_called()
    install.assert_not_called()


def test_cmd_pi_backfill_does_not_exec_pi():
    with mock.patch("lapdog.cli._ensure_lapdog_running", return_value=8126) as ensure:
        with mock.patch("lapdog.cli._install_pi_extension") as install_ext:
            with mock.patch("lapdog.cli._run_pi") as run_pi:
                with mock.patch("lapdog.backfill_pi.backfill") as run_backfill:
                    cli.cmd_pi([], forward_data=True, backfill=True)

    ensure.assert_called_once_with(forward_data=False, detached=True)
    run_backfill.assert_called_once_with("http://localhost:8126")
    install_ext.assert_not_called()
    run_pi.assert_not_called()


def test_cmd_codex_backfill_does_not_exec_codex(monkeypatch):
    monkeypatch.setattr(cli.os, "getcwd", lambda: "/some/cwd")
    expected_cwd = codex_args.resolve_cwd(["--cd", "/some/cwd"])
    with mock.patch("lapdog.cli._ensure_lapdog_running", return_value=8126) as ensure:
        with mock.patch("lapdog.cli._start_codex_watcher") as start_watcher:
            with mock.patch("lapdog.cli._run_codex") as run_codex:
                with mock.patch("lapdog.backfill_codex.backfill") as run_backfill:
                    cli.cmd_codex(["--cd", "/some/cwd"], forward_data=True, backfill=True)

    # forward_data is forced to False during backfill so historical sessions
    # don't accidentally stream to Datadog.
    ensure.assert_called_once_with(forward_data=False, detached=True)
    run_backfill.assert_called_once_with("http://localhost:8126", cwd=expected_cwd)
    start_watcher.assert_not_called()
    run_codex.assert_not_called()
