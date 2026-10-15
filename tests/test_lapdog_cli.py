import importlib
import json
from pathlib import Path
import subprocess
from unittest import mock

import pytest

from lapdog import cli
from lapdog import codex_args
from lapdog.cli import claude as cli_claude
from lapdog.cli import codex as cli_codex
from lapdog.cli import os_runner as cli_os_runner
from lapdog.cli import pi as cli_pi
from lapdog.cli import runtime as cli_runtime
from lapdog.cli import tags as cli_tags

cli_main = importlib.import_module("lapdog.cli.main")


def test_entry_point_preserves_help(monkeypatch, capsys):
    monkeypatch.setattr(cli_main.sys, "argv", ["lapdog", "--help"])

    with pytest.raises(SystemExit) as exc_info:
        cli.main()

    assert exc_info.value.code == 0
    assert capsys.readouterr().out == cli_main.LAPDOG_USAGE + "\n"


@pytest.fixture(autouse=True)
def isolated_codex_capture(monkeypatch, tmp_path):
    from lapdog import codex_launch

    monkeypatch.setattr(
        codex_launch, "run", lambda argv, env, port, owner: cli_codex.run(bin_path=argv[0], argv=argv, env=env)
    )
    monkeypatch.setattr(cli_codex, "install_codex_hooks", mock.Mock())
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))


@pytest.mark.parametrize("args, returncode", [(["--help"], 0), ([], 1)])
def test_module_entry_point(args, returncode):
    result = subprocess.run(
        [cli_main.sys.executable, "-m", "lapdog.cli"] + args,
        cwd=Path(__file__).resolve().parents[1],
        capture_output=True,
        text=True,
        timeout=10,
    )

    assert result.returncode == returncode
    assert result.stdout == (cli_main.LAPDOG_USAGE + "\n" if args else "")
    assert result.stderr == ("" if args else cli_main.LAPDOG_USAGE + "\n")


@pytest.mark.parametrize(
    "argv, handler, expected",
    [
        (["start", "--port", "9126"], "cmd_start", mock.call(sub_cmd_args=["--port", "9126"], forward_data=False)),
        (["stop"], "cmd_stop", mock.call()),
        (["status"], "cmd_status", mock.call()),
        (["uninstall"], "cmd_uninstall", mock.call()),
        (
            ["--forward", "claude", "--model", "opus"],
            "cmd_claude",
            mock.call(sub_cmd_args=["--model", "opus"], forward_data=True, install_plugin=True, backfill=False),
        ),
        (["pi", "--backfill"], "cmd_pi", mock.call(sub_cmd_args=[], forward_data=False, backfill=True)),
        (["--backfill", "codex"], "cmd_codex", mock.call(sub_cmd_args=[], forward_data=False, backfill=True)),
        (
            ["ollama", "launch"],
            "cmd_ollama",
            mock.call(sub_cmd_args=["launch"], forward_data=False, install_plugin=True, backfill=False),
        ),
        (
            ["--forward", "--no-plugin-install", "ollama", "launch", "codex", "--", "resume"],
            "cmd_ollama",
            mock.call(
                sub_cmd_args=["launch", "codex", "--", "resume"],
                forward_data=True,
                install_plugin=False,
                backfill=False,
            ),
        ),
        (
            ["--backfill", "ollama", "launch", "pi"],
            "cmd_ollama",
            mock.call(sub_cmd_args=["launch", "pi"], forward_data=False, install_plugin=True, backfill=True),
        ),
    ],
)
def test_entry_point_dispatches_commands(monkeypatch, argv, handler, expected):
    monkeypatch.setattr(cli_main.sys, "argv", ["lapdog"] + argv)
    with mock.patch.object(cli_main, handler) as command:
        cli.main()
    assert command.call_args_list == [expected]


def test_install_pi_extension_uses_bundled_source(monkeypatch, tmp_path):
    destination = tmp_path / "extensions" / "lapdog.ts"
    monkeypatch.setattr(cli_pi, "_PI_GLOBAL_EXT_DIR", str(destination.parent))
    monkeypatch.setattr(cli_pi, "_PI_EXT_DEST", str(destination))

    cli_pi._install_pi_extension()

    source = Path(cli.__file__).parents[1] / "pi_lapdog_extension.ts"
    assert destination.read_bytes() == source.read_bytes()


@pytest.mark.skipif(cli_os_runner.sys.platform != "win32", reason="Windows-specific subprocess behavior")
@pytest.mark.parametrize("search_path", [False, True])
def test_run_executes_command_on_windows(tmp_path, search_path):
    command = tmp_path / "lapdog-test-command.cmd"
    command.write_text("@exit /b 23\n")

    with pytest.raises(SystemExit) as exc_info:
        cli_os_runner.run(
            bin_path=str(command),
            argv=[str(command)],
            search_path=search_path,
        )

    assert exc_info.value.code == 23


def test_codex_command_is_registered():
    assert "codex" in cli_main.LAPDOG_COMMANDS
    assert "codex" in cli_main.LAPDOG_USAGE


def test_tags_command_is_registered():
    assert "tags" in cli_main.LAPDOG_COMMANDS
    assert "tags" in cli_main.LAPDOG_USAGE
    assert "current instrumented coding-agent session" in cli_main.LAPDOG_USAGE


def test_ensure_refreshes_prices_even_when_server_is_already_running():
    with mock.patch("lapdog.cli.runtime.refresh_price_file") as refresh:
        with mock.patch("lapdog.cli.runtime.lapdog_alive", return_value=True):
            with mock.patch("lapdog.cli.runtime.read_pid_file", return_value=(1234, 8126)):
                assert cli_runtime.ensure_lapdog_running() == 8126
    refresh.assert_called_once_with()


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


def test_stop_all_codex_watchers_terminates_all_watcher_pid_files(tmp_path, monkeypatch):
    (tmp_path / "codex-watcher-key-a.pid").write_text("1111\n")
    (tmp_path / "codex-watcher-key-b.pid").write_text("2222\n")
    (tmp_path / "lapdog.pid").write_text("3333\n")  # should be ignored
    kills = []

    monkeypatch.setattr(cli_codex, "log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli_codex, "_codex_watcher_matches", lambda pid, **kwargs: True)
    monkeypatch.setattr(cli_codex.os, "kill", lambda pid, sig: kills.append((pid, sig)))

    cli_codex._stop_all_codex_watchers()

    assert sorted(kills) == [(1111, cli_codex.signal.SIGTERM), (2222, cli_codex.signal.SIGTERM)]
    assert not (tmp_path / "codex-watcher-key-a.pid").exists()
    assert not (tmp_path / "codex-watcher-key-b.pid").exists()


def test_stop_all_codex_watchers_removes_stale_pid_files(tmp_path, monkeypatch):
    pid_path = tmp_path / "codex-watcher-stale.pid"
    pid_path.write_text("9999\n")
    kill = mock.Mock()

    monkeypatch.setattr(cli_codex, "log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli_codex, "_codex_watcher_matches", lambda pid, **kwargs: False)
    monkeypatch.setattr(cli_codex.os, "kill", kill)

    cli_codex._stop_all_codex_watchers()

    kill.assert_not_called()
    assert not pid_path.exists()


def test_run_codex_injects_lapdog_provider(monkeypatch):
    run_call = {}

    monkeypatch.setattr(cli_codex.shutil, "which", lambda name: "/usr/local/bin/codex")
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setenv("CODEX_THREAD_ID", "outer-codex-thread")
    monkeypatch.setenv("PI_SESSION_ID", "outer-pi-session")
    monkeypatch.setenv("LAPDOG_SESSION_TOKEN", "outer-launch-token")

    def fake_run(bin_path, argv, env):
        run_call["binary"] = bin_path
        run_call["argv"] = argv
        run_call["env"] = env

    monkeypatch.setattr(cli_codex, "run", fake_run)

    cli_codex._run_codex(
        args=["exec", "hello"],
        port=8126,
        proxy_session_key="proxy-key",
        session_token="session-token",
    )

    assert run_call["binary"] == "/usr/local/bin/codex"
    assert run_call["env"]["OPENAI_BASE_URL"] == "http://localhost:8126/codex/proxy/proxy-key/v1"
    assert run_call["env"]["LAPDOG_URL"] == "http://localhost:8126"
    assert run_call["env"]["LAPDOG_SESSION_TOKEN"] == "session-token"
    assert "CODEX_THREAD_ID" not in run_call["env"]
    assert "PI_SESSION_ID" not in run_call["env"]
    assert run_call["argv"][:5] == [
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
    assert run_call["argv"][5:] == ["exec", "hello"]


def _write_installed_plugins(home, plugins):
    plugins_dir = home / ".claude" / "plugins"
    plugins_dir.mkdir(parents=True, exist_ok=True)
    (plugins_dir / "installed_plugins.json").write_text(json.dumps({"version": 2, "plugins": plugins}))


def test_lapdog_plugin_installed_detects_marker(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_claude.Path, "home", classmethod(lambda cls: tmp_path))
    _write_installed_plugins(tmp_path, {cli_claude.LAPDOG_PLUGIN_NAME: [{"scope": "user"}]})
    assert cli_claude._lapdog_claude_code_plugin_installed() is True


def test_lapdog_plugin_installed_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_claude.Path, "home", classmethod(lambda cls: tmp_path))
    assert cli_claude._lapdog_claude_code_plugin_installed() is False


def test_lapdog_plugin_installed_missing_entry(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_claude.Path, "home", classmethod(lambda cls: tmp_path))
    _write_installed_plugins(tmp_path, {"other@market": [{"scope": "user"}]})
    assert cli_claude._lapdog_claude_code_plugin_installed() is False


def test_ensure_lapdog_claude_code_plugin_installed_noop_when_present(monkeypatch):
    monkeypatch.setattr(cli_claude, "_lapdog_claude_code_plugin_installed", lambda: True)
    with mock.patch("lapdog.cli.claude.subprocess.run") as run:
        cli_claude._ensure_lapdog_claude_code_plugin_installed()
    run.assert_not_called()


def test_ensure_lapdog_claude_code_plugin_installed_runs_both_commands(monkeypatch):
    monkeypatch.setattr(cli_claude, "_lapdog_claude_code_plugin_installed", lambda: False)
    monkeypatch.setattr(cli_claude.shutil, "which", lambda name: "/usr/local/bin/claude")
    with mock.patch("lapdog.cli.claude.subprocess.run") as run:
        cli_claude._ensure_lapdog_claude_code_plugin_installed()
    assert run.call_count == 2
    args0 = run.call_args_list[0].args[0]
    args1 = run.call_args_list[1].args[0]
    assert args0 == ["/usr/local/bin/claude", "plugin", "marketplace", "add", cli_claude.LAPDOG_MARKETPLACE_SOURCE]
    assert args1 == ["/usr/local/bin/claude", "plugin", "install", cli_claude.LAPDOG_PLUGIN_NAME]


def test_ensure_lapdog_claude_code_plugin_installed_skips_without_claude_binary(monkeypatch):
    monkeypatch.setattr(cli_claude, "_lapdog_claude_code_plugin_installed", lambda: False)
    monkeypatch.setattr(cli_claude.shutil, "which", lambda name: None)
    with mock.patch("lapdog.cli.claude.subprocess.run") as run:
        cli_claude._ensure_lapdog_claude_code_plugin_installed()
    run.assert_not_called()


def test_ensure_lapdog_claude_code_plugin_installed_continues_on_failure(monkeypatch, capsys):
    monkeypatch.setattr(cli_claude, "_lapdog_claude_code_plugin_installed", lambda: False)
    monkeypatch.setattr(cli_claude.shutil, "which", lambda name: "/usr/local/bin/claude")

    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(returncode=1, cmd=cmd, stderr="boom")

    monkeypatch.setattr(cli_claude.subprocess, "run", fake_run)
    cli_claude._ensure_lapdog_claude_code_plugin_installed()  # must not raise
    err = capsys.readouterr().err
    assert "failed" in err
    assert "claude plugin install lapdog@lapdog" in err


def test_cmd_claude_auto_installs_plugin_by_default():
    with mock.patch("lapdog.cli.claude._ensure_lapdog_claude_code_plugin_installed") as install:
        with mock.patch("lapdog.cli.claude.ensure_lapdog_running", return_value=8126):
            with mock.patch("lapdog.cli.claude.build_running_banner", return_value="banner"):
                with mock.patch("lapdog.cli.claude._run_claude") as run_claude:
                    with mock.patch("lapdog.cli.claude.uuid.uuid4", return_value=mock.Mock(hex="launch-token")):
                        cli_claude.cmd_claude(["--model", "opus"], forward_data=False, install_plugin=True)
    install.assert_called_once_with()
    run_claude.assert_called_once_with(["--model", "opus"], port=8126, session_token="launch-token", launch_bin=None)


def test_cmd_claude_skips_plugin_install_when_opted_out():
    with mock.patch("lapdog.cli.claude._ensure_lapdog_claude_code_plugin_installed") as install:
        with mock.patch("lapdog.cli.claude.ensure_lapdog_running", return_value=8126):
            with mock.patch("lapdog.cli.claude.build_running_banner", return_value="banner"):
                with mock.patch("lapdog.cli.claude._run_claude"):
                    cli_claude.cmd_claude([], forward_data=False, install_plugin=False)
    install.assert_not_called()


def test_cmd_tags_posts_tags_for_instrumented_session(monkeypatch, capsys):
    monkeypatch.setenv("LAPDOG_SESSION_TOKEN", "launch-token")
    monkeypatch.setenv("LAPDOG_URL", "http://localhost:8126")
    monkeypatch.delenv("CODEX_THREAD_ID", raising=False)
    monkeypatch.delenv("PI_SESSION_ID", raising=False)

    with mock.patch(
        "lapdog.cli.tags._post_session_tags",
        return_value={"status": "ok", "session_id": "claude-session"},
    ) as post_tags:
        cli_tags.cmd_tags(["set", "dd_auto_experiment_id:experiment-id", "iteration:2"])

    post_tags.assert_called_once_with(
        "http://localhost:8126",
        "launch-token",
        {"dd_auto_experiment_id": "experiment-id", "iteration": "2"},
        session_id=None,
    )
    assert "Tagged coding-agent session claude-session" in capsys.readouterr().out


def test_cmd_tags_missing_session_message_lists_supported_agents(monkeypatch, capsys):
    monkeypatch.delenv("LAPDOG_SESSION_TOKEN", raising=False)
    monkeypatch.delenv("LAPDOG_URL", raising=False)

    with pytest.raises(SystemExit) as exc_info:
        cli_tags.cmd_tags(["set", "iteration:2"])

    assert exc_info.value.code == 1
    error = capsys.readouterr().err
    assert "No instrumented coding-agent session found" in error
    for launcher in cli_tags._PATH_ROUTABLE_LAUNCHERS:
        assert f"'lapdog {launcher}'" in error


def test_post_session_tags_serializes_target_session_id():
    opener = mock.MagicMock()
    response = mock.MagicMock()
    response.__enter__.return_value.read.return_value = b'{"status": "ok", "session_id": "codex-thread-id"}'
    opener.open.return_value = response

    with mock.patch("lapdog.cli.tags.urllib.request.build_opener", return_value=opener):
        result = cli_tags._post_session_tags(
            "http://localhost:8126",
            "app-launch-token",
            {"iteration": "2"},
            session_id="codex-thread-id",
        )

    request = opener.open.call_args.args[0]
    assert json.loads(request.data) == {
        "session_id": "codex-thread-id",
        "tags": {"iteration": "2"},
    }
    assert result["session_id"] == "codex-thread-id"


def test_cmd_tags_targets_current_codex_thread(monkeypatch, capsys):
    monkeypatch.setenv("LAPDOG_SESSION_TOKEN", "app-launch-token")
    monkeypatch.setenv("LAPDOG_URL", "http://localhost:8126")
    monkeypatch.setenv("CODEX_THREAD_ID", "codex-thread-id")
    monkeypatch.delenv("PI_SESSION_ID", raising=False)

    with mock.patch(
        "lapdog.cli.tags._post_session_tags",
        return_value={"status": "ok", "session_id": "codex-thread-id"},
    ) as post_tags:
        cli_tags.cmd_tags(["set", "iteration:2"])

    post_tags.assert_called_once_with(
        "http://localhost:8126",
        "app-launch-token",
        {"iteration": "2"},
        session_id="codex-thread-id",
    )
    assert "Tagged coding-agent session codex-thread-id" in capsys.readouterr().out


def test_cmd_tags_targets_current_pi_session(monkeypatch, capsys):
    monkeypatch.setenv("LAPDOG_SESSION_TOKEN", "pi-launch-token")
    monkeypatch.setenv("LAPDOG_URL", "http://localhost:8126")
    monkeypatch.delenv("CODEX_THREAD_ID", raising=False)
    monkeypatch.setenv("PI_SESSION_ID", "pi-session-id")

    with mock.patch(
        "lapdog.cli.tags._post_session_tags",
        return_value={"status": "ok", "session_id": "pi-session-id"},
    ) as post_tags:
        cli_tags.cmd_tags(["set", "iteration:2"])

    post_tags.assert_called_once_with(
        "http://localhost:8126",
        "pi-launch-token",
        {"iteration": "2"},
        session_id="pi-session-id",
    )
    assert "Tagged coding-agent session pi-session-id" in capsys.readouterr().out


def test_main_routes_tags_command(monkeypatch):
    monkeypatch.setattr(cli_main.sys, "argv", ["lapdog", "tags", "set", "iteration:2"])
    with mock.patch.object(cli_main, "cmd_tags") as cmd_tags:
        cli_main.main()
    cmd_tags.assert_called_once_with(["set", "iteration:2"])


def test_run_claude_injects_lapdog_session_context(monkeypatch, tmp_path):
    monkeypatch.setattr(cli_claude.shutil, "which", lambda name: "/usr/local/bin/claude")
    debug_log = tmp_path / "claude-code-debug.log"
    monkeypatch.setenv("DDAPM_CLAUDE_DEBUG_LOG", str(debug_log))
    monkeypatch.setenv("CODEX_THREAD_ID", "outer-codex-thread")
    monkeypatch.setenv("PI_SESSION_ID", "outer-pi-session")
    monkeypatch.setenv("LAPDOG_SESSION_TOKEN", "outer-launch-token")
    run = mock.Mock()
    monkeypatch.setattr(cli_claude, "run", run)

    cli_claude._run_claude(["--model", "opus"], port=9126, session_token="launch-token")

    binary = run.call_args.kwargs["bin_path"]
    args = run.call_args.kwargs["argv"]
    env = run.call_args.kwargs["env"]
    assert binary == "/usr/local/bin/claude"
    assert args == ["/usr/local/bin/claude", "--model", "opus"]
    assert env["LAPDOG_URL"] == "http://localhost:9126"
    assert env["DDAPM_GATEWAY_URL"] == "http://localhost:9126/claude/proxy"
    assert env["TEST_AGENT_URL"] == "http://localhost:9126/info"
    assert env["LAPDOG_SESSION_TOKEN"] == "launch-token"
    assert env["DDAPM_CLAUDE_DEBUG_LOG"] == str(debug_log)
    preload = Path(cli.__file__).parents[1] / "claude_intercept.mjs"
    assert preload.is_file()
    assert env["BUN_OPTIONS"].startswith(f"--preload {preload.as_posix()}")
    assert "launcher exec preload=" in debug_log.read_text()
    assert "CODEX_THREAD_ID" not in env
    assert "PI_SESSION_ID" not in env


def test_run_pi_injects_lapdog_session_context(monkeypatch):
    monkeypatch.setattr(cli_pi.shutil, "which", lambda name: "/usr/local/bin/pi")
    monkeypatch.setenv("CODEX_THREAD_ID", "outer-codex-thread")
    monkeypatch.setenv("PI_SESSION_ID", "outer-pi-session")
    monkeypatch.setenv("LAPDOG_SESSION_TOKEN", "outer-launch-token")
    run = mock.Mock()
    monkeypatch.setattr(cli_pi, "run", run)

    cli_pi._run_pi(["--model", "anthropic/claude-opus-4-1"], port=9126, session_token="pi-launch-token")

    binary = run.call_args.kwargs["bin_path"]
    args = run.call_args.kwargs["argv"]
    env = run.call_args.kwargs["env"]
    assert binary == "/usr/local/bin/pi"
    assert args == ["/usr/local/bin/pi", "--model", "anthropic/claude-opus-4-1"]
    assert env["LAPDOG_URL"] == "http://localhost:9126"
    assert env["LAPDOG_SESSION_TOKEN"] == "pi-launch-token"
    assert "CODEX_THREAD_ID" not in env
    assert "PI_SESSION_ID" not in env


def test_cmd_pi_injects_unique_session_token():
    with mock.patch("lapdog.cli.pi.ensure_lapdog_running", return_value=8126) as ensure:
        with mock.patch("lapdog.cli.pi._install_pi_extension") as install_ext:
            with mock.patch("lapdog.cli.pi._run_pi") as run_pi:
                with mock.patch("lapdog.cli.pi.uuid.uuid4", return_value=mock.Mock(hex="pi-launch-token")):
                    with mock.patch("lapdog.cli.pi.build_running_banner", return_value="banner"):
                        cli_pi.cmd_pi(["--model", "anthropic/claude-opus-4-1"], forward_data=True)

    ensure.assert_called_once_with(True, detached=True)
    install_ext.assert_called_once_with()
    run_pi.assert_called_once_with(
        args=["--model", "anthropic/claude-opus-4-1"],
        port=8126,
        session_token="pi-launch-token",
        launch_bin=None,
    )


def test_run_codex_falls_back_without_openai_api_key(monkeypatch):
    run_call = {}

    monkeypatch.setattr(cli_codex.shutil, "which", lambda name: "/usr/local/bin/codex")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)

    def fake_run(bin_path, argv, env):
        run_call["argv"] = argv
        run_call["env"] = env

    monkeypatch.setattr(cli_codex, "run", fake_run)

    cli_codex._run_codex(args=["exec", "hello"], port=8126)

    assert run_call["env"]["OPENAI_BASE_URL"] == "http://localhost:8126/codex/proxy/v1"
    assert run_call["argv"] == ["/usr/local/bin/codex", "exec", "hello"]


def test_backfill_flag_parses():
    parsed = cli_main._parse_lapdog_args(["--backfill"])
    assert parsed.backfill is True
    assert parsed.forward is False


def test_subcommand_args_are_not_reparsed_as_lapdog_args():
    lapdog_args, remaining = cli_main._parse_command(["claude", "--backfill"])

    assert lapdog_args == []
    assert remaining == ["claude", "--backfill"]


def test_command_local_backfill_is_consumed():
    args, backfill = cli_main._consume_backfill_arg(["--model", "opus", "--backfill"])

    assert args == ["--model", "opus"]
    assert backfill is True


def test_command_local_backfill_after_double_dash_is_forwarded():
    args, backfill = cli_main._consume_backfill_arg(["--", "--backfill"])

    assert args == ["--", "--backfill"]
    assert backfill is False


def test_cmd_claude_backfill_does_not_exec_claude():
    with mock.patch("lapdog.cli.claude.ensure_lapdog_running", return_value=8126) as ensure:
        with mock.patch("lapdog.cli.claude._run_claude") as run_claude:
            with mock.patch("lapdog.cli.claude._ensure_lapdog_claude_code_plugin_installed") as install:
                with mock.patch("lapdog.backfill_claude.backfill") as run_backfill:
                    cli_claude.cmd_claude([], forward_data=True, install_plugin=True, backfill=True)

    ensure.assert_called_once_with(forward_data=False, detached=True)
    run_backfill.assert_called_once_with("http://localhost:8126")
    run_claude.assert_not_called()
    install.assert_not_called()


def test_cmd_pi_backfill_does_not_exec_pi():
    with mock.patch("lapdog.cli.pi.ensure_lapdog_running", return_value=8126) as ensure:
        with mock.patch("lapdog.cli.pi._install_pi_extension") as install_ext:
            with mock.patch("lapdog.cli.pi._run_pi") as run_pi:
                with mock.patch("lapdog.backfill_pi.backfill") as run_backfill:
                    cli_pi.cmd_pi([], forward_data=True, backfill=True)

    ensure.assert_called_once_with(forward_data=False, detached=True)
    run_backfill.assert_called_once_with("http://localhost:8126")
    install_ext.assert_not_called()
    run_pi.assert_not_called()


def test_cmd_codex_backfill_does_not_exec_codex(monkeypatch):
    monkeypatch.setattr(cli_codex.os, "getcwd", lambda: "/some/cwd")
    expected_cwd = codex_args.resolve_cwd(["--cd", "/some/cwd"])
    with mock.patch("lapdog.cli.codex.ensure_lapdog_running", return_value=8126) as ensure:
        with mock.patch("lapdog.cli.codex.install_codex_hooks") as start_watcher:
            with mock.patch("lapdog.cli.codex._run_codex") as run_codex:
                with mock.patch("lapdog.backfill_codex.backfill") as run_backfill:
                    cli_codex.cmd_codex(["--cd", "/some/cwd"], forward_data=True, backfill=True)

    # forward_data is forced to False during backfill so historical sessions
    # don't accidentally stream to Datadog.
    ensure.assert_called_once_with(forward_data=False, detached=True)
    run_backfill.assert_called_once_with("http://localhost:8126", cwd=expected_cwd)
    start_watcher.assert_not_called()
    run_codex.assert_not_called()


def test_canonical_launcher_bare_name():
    assert cli_main._canonical_launcher("claude") == "claude"
    assert cli_main._canonical_launcher("Codex") == "codex"


def test_canonical_launcher_path_resolving_to_launcher(monkeypatch, tmp_path):
    # Claude installs as a versioned binary with a `claude` symlink. A path
    # invocation that resolves to the same file as `which claude` must map to
    # the `claude` command so it routes to cmd_claude, not cmd_exec (MLOB-7870).
    real = tmp_path / "versions" / "2.1.215"
    real.parent.mkdir(parents=True)
    real.write_text("#!/bin/sh\n")
    link = tmp_path / "bin" / "claude"
    link.parent.mkdir(parents=True)
    link.symlink_to(real)

    monkeypatch.setattr(cli_main.shutil, "which", lambda name: str(link) if name == "claude" else None)

    # Invoked via the symlink or via the versioned real path — both resolve to
    # the same target as `which claude`.
    assert cli_main._canonical_launcher(str(link)) == "claude"
    assert cli_main._canonical_launcher(str(real)) == "claude"


def test_canonical_launcher_ignores_unknown_targets(monkeypatch):
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: None)
    assert cli_main._canonical_launcher("python") is None
    assert cli_main._canonical_launcher("/usr/bin/python") is None


def test_canonical_launcher_path_not_matching_which_falls_through(monkeypatch, tmp_path):
    # A path whose basename is `claude` but which does not resolve to the
    # managed claude binary must NOT be rerouted.
    other = tmp_path / "claude"
    other.write_text("#!/bin/sh\n")
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: None)
    assert cli_main._canonical_launcher(str(other)) is None


def test_main_routes_full_path_claude_to_cmd_claude(monkeypatch, tmp_path):
    claude = tmp_path / "claude"
    claude.write_text("#!/bin/sh\n")
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: str(claude) if name == "claude" else None)
    monkeypatch.setattr(cli_main.sys, "argv", ["lapdog", str(claude)])
    with mock.patch.object(cli_main, "cmd_claude") as cmd_claude:
        with mock.patch.object(cli_main, "cmd_exec") as cmd_exec:
            cli_main.main()

    cmd_claude.assert_called_once()
    cmd_exec.assert_not_called()


def test_main_routes_unknown_command_to_cmd_exec(monkeypatch):
    monkeypatch.setattr(cli_main.shutil, "which", lambda name: None)
    monkeypatch.setattr(cli_main.sys, "argv", ["lapdog", "/usr/bin/python", "app.py"])
    with mock.patch.object(cli_main, "cmd_claude") as cmd_claude:
        with mock.patch.object(cli_main, "cmd_exec") as cmd_exec:
            cli_main.main()

    cmd_exec.assert_called_once()
    cmd_claude.assert_not_called()


def test_start_lapdog_uses_dedicated_server_module(tmp_path, monkeypatch):
    process = mock.Mock(pid=1234)
    popen = mock.Mock(return_value=process)
    monkeypatch.setattr(cli_runtime, "log_file_path", lambda: str(tmp_path / "lapdog.log"))
    monkeypatch.setattr(cli_runtime, "_write_pid_file", mock.Mock())
    monkeypatch.setattr(cli_runtime, "_wait_for_lapdog", mock.Mock())
    monkeypatch.setattr(cli_runtime.subprocess, "Popen", popen)

    cli_runtime.start_lapdog(8126)

    assert popen.call_args.args[0] == [
        cli_runtime.sys.executable,
        "-m",
        "lapdog.server",
        "--disable-llmobs-data-forwarding",
    ]


@pytest.mark.parametrize("args", [[], ["resume", "--last"], ["--cd", "/repo"]])
def test_cmd_codex_installs_hooks_and_preserves_launch_arguments(args):
    with mock.patch.object(cli_codex, "ensure_lapdog_running", return_value=12345), mock.patch.object(
        cli_codex, "install_codex_hooks"
    ) as install, mock.patch.object(cli_codex, "_stop_all_codex_watchers") as stop, mock.patch.object(
        cli_codex, "_run_codex"
    ) as launch:
        cli_codex.cmd_codex(args, forward_data=False)
    install.assert_called_once_with(12345, "")
    stop.assert_called_once_with(lapdog_url="http://localhost:12345")
    assert launch.call_args.kwargs["args"] == args
    assert launch.call_args.kwargs["port"] == 12345
    assert launch.call_args.kwargs["proxy_session_key"]


@pytest.mark.parametrize("args", [["--no-daemon"], ["resume", "--no-daemon", "--last"]])
def test_run_codex_does_not_duplicate_no_daemon(args, monkeypatch):
    monkeypatch.setattr(cli_codex.shutil, "which", lambda _: "/usr/bin/codex")
    with mock.patch.object(cli_codex, "run") as run:
        cli_codex._run_codex(args=args)
    assert run.call_args.kwargs["argv"].count("--no-daemon") == 1
    assert run.call_args.kwargs["argv"][-len(args) :] == args


def test_cmd_codex_launches_desktop_without_installing_global_hooks():
    with mock.patch.object(cli_codex, "install_codex_hooks") as install, mock.patch.object(
        cli_codex, "ensure_lapdog_running", return_value=12345
    ), mock.patch("lapdog.cli.codex_desktop.launch") as launch:
        cli_codex.cmd_codex(["app", "/repo"], forward_data=False)
    install.assert_not_called()
    assert launch.call_args.args[:2] == ("/repo", 12345)
    assert launch.call_args.args[2]


def test_cmd_codex_rejects_unsupported_version_before_launch(capsys):
    with mock.patch.object(cli_codex, "ensure_lapdog_running", return_value=12345), mock.patch.object(
        cli_codex, "install_codex_hooks", side_effect=RuntimeError("requires Codex CLI 0.124.0")
    ), mock.patch.object(cli_codex, "_run_codex") as launch:
        with pytest.raises(SystemExit) as exc:
            cli_codex.cmd_codex([], forward_data=False)
    assert exc.value.code == 1
    assert "0.124.0" in capsys.readouterr().err
    launch.assert_not_called()


@pytest.mark.parametrize(
    "command, matches",
    [
        ("python -m lapdog.codex_watcher --lapdog-url http://localhost:12345", True),
        ("python -m lapdog.codex_watcher --lapdog-url http://localhost:8126", False),
        ("python other.py --lapdog-url http://localhost:12345", False),
        (None, False),
    ],
)
def test_migration_cleanup_verifies_watcher_and_collector(monkeypatch, command, matches):
    monkeypatch.setattr(cli_codex, "process_exists", lambda pid: True)
    monkeypatch.setattr(cli_codex, "_codex_watcher_command", lambda pid: command)
    assert cli_codex._codex_watcher_matches(4242, lapdog_url="http://localhost:12345") is matches
