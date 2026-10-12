import sys
from unittest import mock

import pytest

from lapdog.cli import os_runner


@pytest.mark.parametrize("extension", ["exe", "cmd", "BAT"])
@pytest.mark.parametrize("search_path", [False, True])
def test_windows_run_waits_for_child_after_console_interrupt(monkeypatch, extension, search_path):
    monkeypatch.setattr(sys, "platform", "win32")
    binary = f"C:\\bin with spaces\\agent.{extension}"
    proc = mock.Mock()
    proc.wait.side_effect = [KeyboardInterrupt, 23]
    with mock.patch.object(os_runner.subprocess, "Popen", return_value=proc) as popen:
        with pytest.raises(SystemExit) as error:
            os_runner.run(binary, [binary, "argument with spaces"], env={"PATH": "original"}, search_path=search_path)
    assert error.value.code == 23
    assert proc.wait.call_count == 2
    proc.kill.assert_not_called()
    expected = {"shell": True} if extension != "exe" else ({} if search_path else {"executable": binary})
    popen.assert_called_once_with(
        [binary, "argument with spaces"],
        env={"PATH": "original"},
        stdin=None,
        stdout=None,
        stderr=None,
        **expected,
    )


def test_posix_wait_propagates_interrupt(monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    proc = mock.Mock()
    proc.wait.side_effect = KeyboardInterrupt
    with pytest.raises(KeyboardInterrupt):
        os_runner.wait_for_exit(proc)
