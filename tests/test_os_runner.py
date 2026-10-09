import sys
from unittest import mock

import pytest

from lapdog.cli import os_runner


def test_windows_run_waits_for_child_after_console_interrupt(monkeypatch):
    monkeypatch.setattr(sys, "platform", "win32")
    proc = mock.Mock()
    proc.wait.side_effect = [KeyboardInterrupt, 23]
    with mock.patch.object(os_runner.subprocess, "Popen", return_value=proc) as popen:
        with pytest.raises(SystemExit) as error:
            os_runner.run("agent.exe", ["agent.exe", "argument with spaces"], env={"PATH": "original"})
    assert error.value.code == 23
    assert proc.wait.call_count == 2
    proc.kill.assert_not_called()
    popen.assert_called_once_with(
        ["agent.exe", "argument with spaces"],
        env={"PATH": "original"},
        stdin=None,
        stdout=None,
        stderr=None,
        executable="agent.exe",
    )


def test_posix_wait_propagates_interrupt(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    proc = mock.Mock()
    proc.wait.side_effect = KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        os_runner.wait_for_exit(proc)
