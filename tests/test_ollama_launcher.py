import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
from unittest import mock

import pytest

from lapdog import ollama_launcher
from lapdog.cli import claude as cli_claude
from lapdog.cli import codex as cli_codex
from lapdog.cli import ollama as cli_ollama
from lapdog.cli import os_runner
from lapdog.cli import pi as cli_pi


@pytest.mark.skipif(os.name == "nt", reason="POSIX executable fixture")
@pytest.mark.parametrize("exit_code", [0, 7])
@pytest.mark.parametrize("args", [["launch"], ["launch", "codex", "--", "resume", "session with spaces"]])
def test_menu_wrappers_forward_probes_restore_path_and_are_removed(monkeypatch, tmp_path, exit_code, args):
    bin_dir = tmp_path / "bin with spaces"
    bin_dir.mkdir()
    agent = bin_dir / "codex"
    agent.write_text(
        "#!/bin/sh\nexec "
        + shlex.quote(sys.executable)
        + " -c "
        + shlex.quote("import json, os, sys; print(json.dumps([sys.argv[1:], os.environ['PATH']]))")
        + ' "$@"\n'
    )
    agent.chmod(0o700)
    ollama = bin_dir / "ollama"
    ollama.write_text(f'#!/bin/sh\ncodex --version "argument with spaces"\nexit {exit_code}\n')
    ollama.chmod(0o700)
    monkeypatch.setenv("PATH", str(bin_dir))
    # Let the subprocess import this checkout even without an editable install.
    monkeypatch.setenv("PYTHONPATH", str(Path(__file__).resolve().parents[1]))
    real_run = subprocess.run
    wrapper_dirs = []

    def run_child(argv, env):
        assert argv == [str(ollama)] + args
        wrapper_dir = Path(env["PATH"].split(os.pathsep)[0])
        wrapper_dirs.append(wrapper_dir)
        assert (wrapper_dir / "codex").is_file()
        assert not (wrapper_dir / "claude").exists()
        assert not (wrapper_dir / "pi").exists()
        result = real_run(argv, env=env, capture_output=True, text=True)
        assert result.stderr == ""
        assert json.loads(result.stdout) == [["--version", "argument with spaces"], str(bin_dir)]
        return result

    monkeypatch.setattr(ollama_launcher.subprocess, "run", run_child)
    assert ollama_launcher.run_launch(str(ollama), args, False, False) == exit_code
    assert os.environ["PATH"] == str(bin_dir)
    assert all(not path.exists() for path in wrapper_dirs)


@pytest.mark.parametrize("agent", ["claude", "codex", "pi"])
def test_selected_agent_receives_final_arguments_and_options(monkeypatch, tmp_path, agent):
    config = tmp_path / "launch.json"
    binary = f"/real/bin/{agent}"
    config.write_text(
        json.dumps(
            {
                "path": "/real/bin",
                "binaries": {agent: binary},
                "forward_data": True,
                "install_plugin": False,
            }
        )
    )
    args = ["--model", "example", "resume", "session-id"]
    monkeypatch.setenv("PATH", "/temporary/wrappers:/real/bin")
    monkeypatch.setattr(sys, "argv", ["wrapper", str(config), agent] + args)
    with mock.patch.object({"claude": cli_claude, "codex": cli_codex, "pi": cli_pi}[agent], f"cmd_{agent}") as launch:
        ollama_launcher.main()
    assert os.environ["PATH"] == "/real/bin"
    if agent == "claude":
        launch.assert_called_once_with(args, True, False, launch_bin=binary)
    elif agent == "codex":
        launch.assert_called_once_with(args, True, launch_bin=binary, capture_proxy=False)
    else:
        launch.assert_called_once_with(args, True, launch_bin=binary)


@pytest.mark.parametrize("command", ["list", "install", "update", "remove", "--version", "--help"])
def test_pi_maintenance_commands_bypass_instrumentation(command):
    assert ollama_launcher._maintenance_command("pi", [command])
    assert not ollama_launcher._maintenance_command("pi", ["--resume"])
    assert not ollama_launcher._maintenance_command("pi", [])


def test_codex_menu_launch_preserves_ollama_provider(monkeypatch):
    monkeypatch.setattr(cli_codex.shutil, "which", lambda name: f"/real/bin/{name}")
    monkeypatch.setenv("OPENAI_API_KEY", "ollama")
    monkeypatch.setenv("OPENAI_BASE_URL", "http://localhost:11434/v1")
    args = ["--profile", "ollama-launch", "-m", "example"]
    with mock.patch.object(cli_codex, "run") as run:
        cli_codex._run_codex(args, port=9126, session_token="session", capture_proxy=False)
    assert run.call_args.kwargs["argv"] == ["/real/bin/codex"] + args
    env = run.call_args.kwargs["env"]
    assert env["OPENAI_BASE_URL"] == "http://localhost:11434/v1"
    assert env["OPENAI_API_KEY"] == "ollama"
    assert env["LAPDOG_URL"] == "http://localhost:9126"
    assert env["LAPDOG_SESSION_TOKEN"] == "session"


@pytest.mark.parametrize(
    "args",
    [
        ["launch"],
        ["launch", "claude"],
        ["launch", "pi"],
        ["launch", "codex", "--", "resume", "session-id"],
        ["launch", "opencode"],
    ],
)
def test_launch_uses_wrappers(args):
    with mock.patch.object(cli_ollama.shutil, "which", return_value="/real/bin/ollama"):
        with mock.patch.object(cli_ollama, "run_launch", return_value=7) as menu:
            with pytest.raises(SystemExit) as error:
                cli_ollama.cmd_ollama(args, forward_data=True, install_plugin=False)
    menu.assert_called_once_with("/real/bin/ollama", args, True, False)
    assert error.value.code == 7


@pytest.mark.skipif(os.name == "nt", reason="POSIX interrupt behavior")
def test_menu_cleans_up_after_interrupt(monkeypatch):
    directories = []

    def interrupt(argv, env):
        directories.append(Path(env["PATH"].split(os.pathsep)[0]))
        raise KeyboardInterrupt

    monkeypatch.setattr(ollama_launcher.shutil, "which", lambda name: None)
    monkeypatch.setattr(ollama_launcher.subprocess, "run", interrupt)
    assert ollama_launcher.run_launch("/fake/ollama", ["launch"], False, False) == 130
    assert directories
    assert all(not directory.exists() for directory in directories)


@pytest.mark.parametrize("agent", ["codex", "pi"])
def test_wrapper_instruments_final_agent_arguments(monkeypatch, tmp_path, agent):
    config = tmp_path / "launch.json"
    binary = f"/real/bin/{agent}"
    config.write_text(
        json.dumps(
            {
                "path": "/real/bin",
                "binaries": {agent: binary},
                "forward_data": True,
                "install_plugin": False,
            }
        )
    )
    session_id = "123e4567-e89b-12d3-a456-426614174000"
    args = ["--model", "example"]
    if agent == "codex":
        args.extend(["--cd", str(tmp_path), "resume", session_id, "--all"])
    monkeypatch.setattr(sys, "argv", ["wrapper", str(config), agent] + args)
    monkeypatch.setenv("PATH", "/temporary/wrappers:/real/bin")
    monkeypatch.setenv("OPENAI_API_KEY", "ollama")
    with mock.patch.object(
        cli_codex if agent == "codex" else cli_pi, "ensure_lapdog_running", return_value=9126
    ) as ensure:
        with mock.patch.object(cli_pi, "_install_pi_extension") as install:
            with mock.patch.object(cli_codex, "_start_codex_watcher") as watcher:
                with mock.patch.object(cli_codex if agent == "codex" else cli_pi, "run") as run:
                    ollama_launcher.main()
    ensure.assert_called_once_with(True, detached=True)
    if agent == "codex":
        assert watcher.call_args.kwargs["cwd"] == str(tmp_path)
        assert watcher.call_args.kwargs["resume_mode"] is True
        assert watcher.call_args.kwargs["resume_session_id"] == session_id
        assert watcher.call_args.kwargs["resume_all_cwds"] is True
        install.assert_not_called()
    else:
        install.assert_called_once_with()
        watcher.assert_not_called()
    assert run.call_args.kwargs["bin_path"] == binary
    assert run.call_args.kwargs["argv"] == [binary] + args
    env = run.call_args.kwargs["env"]
    assert env["LAPDOG_URL"] == "http://localhost:9126"
    assert env["LAPDOG_SESSION_TOKEN"]


@pytest.mark.parametrize("agent", ["claude", "codex", "pi"])
@pytest.mark.parametrize("suffix", ["", ".exe"])
def test_windows_entry_point_uses_adjacent_config(monkeypatch, tmp_path, agent, suffix):
    wrapper = tmp_path / "wrappers with spaces" / (agent + suffix)
    args = ["--model", "example", "argument with spaces", 'a"b', ""]
    monkeypatch.setattr(sys, "argv", [str(wrapper)] + args)
    with mock.patch.object(ollama_launcher, "_launch_agent") as launch:
        ollama_launcher.windows_main()
    launch.assert_called_once_with(wrapper.parent / "launch.json", agent, args)


def test_windows_wrapper_generation_uses_console_executables(monkeypatch, tmp_path):
    scripts = pytest.importorskip("distlib.scripts")
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(sys, "executable", r"C:\Python with spaces\python.exe")
    with mock.patch.object(scripts, "ScriptMaker") as factory:
        ollama_launcher._write_wrappers(tmp_path, ["claude", "codex", "pi"])
    factory.assert_called_once_with(None, str(tmp_path))
    maker = factory.return_value
    assert maker.executable == '"C:\\Python with spaces\\python.exe"'
    assert maker.variants == {""}
    assert maker.make.call_args_list == [
        mock.call(f"{agent} = lapdog.ollama_launcher:windows_main") for agent in ("claude", "codex", "pi")
    ]


def test_windows_launch_waits_through_interrupt_before_cleanup(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(ollama_launcher.shutil, "which", lambda name: None)
    proc = mock.MagicMock()
    proc.__enter__.return_value = proc
    directories = []

    def start(argv, env):
        assert argv == ["/fake/ollama", "launch", "codex"]
        directories.append(Path(env["PATH"].split(os.pathsep)[0]))
        return proc

    def wait():
        assert (directories[0] / "launch.json").is_file()
        if proc.wait.call_count == 1:
            raise KeyboardInterrupt
        return 23

    proc.wait.side_effect = wait
    with mock.patch.object(ollama_launcher, "_write_wrappers"):
        with mock.patch.object(ollama_launcher.subprocess, "Popen", side_effect=start):
            assert ollama_launcher.run_launch("/fake/ollama", ["launch", "codex"], False, False) == 23
    assert proc.wait.call_count == 2
    proc.kill.assert_not_called()
    assert not directories[0].exists()


def test_maintenance_command_uses_shared_runner(monkeypatch, tmp_path):
    config = tmp_path / "launch.json"
    config.write_text(json.dumps({"path": "original-path", "binaries": {"pi": "pi.cmd"}}))
    monkeypatch.setenv("PATH", "wrapper-path")
    with mock.patch.object(os_runner, "run") as run:
        ollama_launcher._launch_agent(config, "pi", ["list"])
    run.assert_called_once_with("pi.cmd", ["pi.cmd", "list"])
    assert os.environ["PATH"] == "original-path"


@pytest.mark.skipif(sys.platform != "win32", reason="Runs native Windows executables")
@pytest.mark.parametrize("exit_code", [0, 23])
@pytest.mark.parametrize("agent_format", ["exe", "cmd"])
def test_windows_wrappers_execute_and_cleanup(monkeypatch, tmp_path, exit_code, agent_format):
    from distlib.scripts import ScriptMaker

    source = tmp_path / "source"
    source.mkdir()
    binaries = tmp_path / "bin with spaces"
    binaries.mkdir()
    (source / "codex.py").write_text(
        "#!python\n"
        "import json, os, sys\n"
        "from pathlib import Path\n"
        "Path(os.environ['LAPDOG_TEST_RESULT']).write_text(json.dumps([sys.argv[1:], os.environ['PATH']]))\n"
        f"sys.exit({exit_code})\n"
    )
    (source / "ollama.py").write_text(
        "#!python\n"
        "import subprocess, sys\n"
        "sys.exit(subprocess.run(['codex', '--version'] + sys.argv[2:]).returncode)\n"
    )
    maker = ScriptMaker(str(source), str(binaries))
    if agent_format == "exe":
        maker.make("codex.py")
    else:
        # npm-installed agents commonly expose .cmd launchers on Windows.
        (binaries / "codex.cmd").write_text(
            f'@echo off\n"{sys.executable}" "{source / "codex.py"}" %*\nexit /b %errorlevel%\n'
        )
    maker.make("ollama.py")
    result_file = tmp_path / "result.json"
    monkeypatch.setenv("PATH", str(binaries))
    monkeypatch.setenv("LAPDOG_TEST_RESULT", str(result_file))
    monkeypatch.setenv("PYTHONPATH", str(Path(__file__).resolve().parents[1]))
    write_wrappers = ollama_launcher._write_wrappers
    directories = []

    def record_wrappers(directory, agents):
        directories.append(directory)
        write_wrappers(directory, agents)
        assert (directory / "codex.exe").read_bytes().startswith(b"MZ")
        assert not (directory / "pi.exe").exists()

    monkeypatch.setattr(ollama_launcher, "_write_wrappers", record_wrappers)
    args = ["argument with spaces"]
    if agent_format == "exe":
        args.extend(['a"b', "", "a&b", "%PATH%", "trailing\\"])
    assert ollama_launcher.run_launch(str(binaries / "ollama.exe"), ["launch"] + args, False, False) == exit_code
    assert json.loads(result_file.read_text()) == [["--version"] + args, str(binaries)]
    assert all(not directory.exists() for directory in directories)
    assert os.environ["PATH"] == str(binaries)
