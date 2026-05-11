"""Tracer injection helpers for lapdog: builds an instrumented environment for Python processes."""

import importlib.util
import os
import sys
from typing import Dict
from typing import Optional


def _lapdog_bootstrap_dir() -> str:
    return os.path.join(os.path.dirname(__file__), "bootstrap")


def _lapdog_ddtrace_site_packages() -> Optional[str]:
    """Return the site-packages dir containing lapdog's own ddtrace, or None if not installed."""
    spec = importlib.util.find_spec("ddtrace")
    if spec is None or spec.origin is None:
        return None
    return os.path.dirname(os.path.dirname(spec.origin))


def build_instrumented_env(
    port: int,
    base_env: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Return a copy of base_env with tracer env vars injected for Python processes."""
    env = dict(base_env if base_env is not None else os.environ)

    env["DD_TRACE_AGENT_URL"] = f"http://127.0.0.1:{port}"
    env["DD_TRACE_AGENT_HOST"] = "127.0.0.1"
    env["DD_TRACE_AGENT_PORT"] = str(port)
    env["DD_LLMOBS_ENABLED"] = "true"
    env["DD_LLMOBS_AGENTLESS_ENABLED"] = "false"

    bootstrap = _lapdog_bootstrap_dir()
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{bootstrap}{os.pathsep}{existing}" if existing else bootstrap

    lapdog_sp = _lapdog_ddtrace_site_packages()
    if lapdog_sp:
        env["_LAPDOG_DDTRACE_SITE_PACKAGES"] = lapdog_sp
        env["_LAPDOG_PYTHON_VERSION"] = f"{sys.version_info.major}.{sys.version_info.minor}"

    return env
