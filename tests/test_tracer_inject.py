"""Tests for lapdog.tracer_inject and lapdog/bootstrap/sitecustomize.py."""
import os
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

from lapdog import tracer_inject


BOOTSTRAP_DIR = str(Path(tracer_inject.__file__).parent / "bootstrap")


class TestBuildInstrumentedEnv:
    def test_sets_dd_vars(self) -> None:
        env = tracer_inject.build_instrumented_env(port=8126, base_env={})
        assert env["DD_TRACE_AGENT_URL"] == "http://127.0.0.1:8126"
        assert env["DD_TRACE_AGENT_HOST"] == "127.0.0.1"
        assert env["DD_TRACE_AGENT_PORT"] == "8126"
        assert env["DD_LLMOBS_ENABLED"] == "true"
        assert env["DD_LLMOBS_AGENTLESS_ENABLED"] == "false"

    def test_injects_bootstrap_pythonpath(self) -> None:
        env = tracer_inject.build_instrumented_env(port=8126, base_env={})
        assert env["PYTHONPATH"].startswith(BOOTSTRAP_DIR)

    def test_prepends_to_existing_pythonpath(self) -> None:
        env = tracer_inject.build_instrumented_env(port=8126, base_env={"PYTHONPATH": "/existing"})
        parts = env["PYTHONPATH"].split(os.pathsep)
        assert parts[0] == BOOTSTRAP_DIR
        assert "/existing" in parts

    def test_sets_lapdog_site_packages_when_ddtrace_installed(self) -> None:
        fake_sp = "/fake/site-packages"
        with mock.patch("lapdog.tracer_inject._lapdog_ddtrace_site_packages", return_value=fake_sp):
            env = tracer_inject.build_instrumented_env(port=8126, base_env={})
        assert env["_LAPDOG_DDTRACE_SITE_PACKAGES"] == fake_sp

    def test_sets_lapdog_python_version_when_ddtrace_installed(self) -> None:
        expected = f"{sys.version_info.major}.{sys.version_info.minor}"
        with mock.patch("lapdog.tracer_inject._lapdog_ddtrace_site_packages", return_value="/fake/sp"):
            env = tracer_inject.build_instrumented_env(port=8126, base_env={})
        assert env["_LAPDOG_PYTHON_VERSION"] == expected

    def test_no_lapdog_vars_when_ddtrace_not_installed(self) -> None:
        with mock.patch("lapdog.tracer_inject._lapdog_ddtrace_site_packages", return_value=None):
            env = tracer_inject.build_instrumented_env(port=8126, base_env={})
        assert "_LAPDOG_DDTRACE_SITE_PACKAGES" not in env
        assert "_LAPDOG_PYTHON_VERSION" not in env

    def test_uses_os_environ_as_base_by_default(self) -> None:
        with mock.patch.dict(os.environ, {"MY_VAR": "hello"}):
            env = tracer_inject.build_instrumented_env(port=8126)
        assert env["MY_VAR"] == "hello"


class TestSitecustomize:
    @pytest.fixture()
    def fake_broken_ddtrace(self, tmp_path: Path) -> str:
        """Create a directory containing a ddtrace package that raises ImportError on import.

        Placing this directory early in PYTHONPATH shadows the real ddtrace from the
        venv's site-packages, letting us test the "ddtrace not importable" paths without
        needing a Python install that lacks ddtrace.
        """
        ddtrace_dir = tmp_path / "ddtrace"
        ddtrace_dir.mkdir()
        (ddtrace_dir / "__init__.py").write_text("raise ImportError(\"No module named 'ddtrace'\")")
        return str(tmp_path)

    def test_loads_ddtrace_when_installed(self) -> None:
        existing = os.environ.get("PYTHONPATH", "")
        pythonpath = f"{BOOTSTRAP_DIR}{os.pathsep}{existing}" if existing else BOOTSTRAP_DIR
        result = subprocess.run(
            [sys.executable, "-c", "import ddtrace; print('ok')"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": pythonpath},
        )
        assert result.returncode == 0, result.stderr
        assert "ok" in result.stdout

    def test_exits_with_message_when_ddtrace_missing(self, fake_broken_ddtrace: str) -> None:
        result = subprocess.run(
            [sys.executable, "-c", "print('should not reach')"],
            capture_output=True,
            text=True,
            env={"PYTHONPATH": f"{BOOTSTRAP_DIR}{os.pathsep}{fake_broken_ddtrace}"},
        )
        assert result.returncode == 1
        assert "ddtrace is not installed" in result.stderr

    def test_exits_with_version_mismatch_message_on_abi_error(self, fake_broken_ddtrace: str) -> None:
        result = subprocess.run(
            [sys.executable, "-c", "print('should not reach')"],
            capture_output=True,
            text=True,
            env={
                "PYTHONPATH": f"{BOOTSTRAP_DIR}{os.pathsep}{fake_broken_ddtrace}",
                "_LAPDOG_DDTRACE_SITE_PACKAGES": "/nonexistent/site-packages",
                "_LAPDOG_PYTHON_VERSION": "3.99",
            },
        )
        assert result.returncode == 1
        assert "version mismatch" in result.stderr
        assert "3.99" in result.stderr
