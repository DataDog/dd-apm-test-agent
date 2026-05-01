"""Tracer injection helpers for lapdog: builds an instrumented environment for Python processes."""
import importlib.util
import os
import sys
from typing import Dict
from typing import Optional


def _ddtrace_bootstrap_path() -> Optional[str]:
    """Return the ddtrace sitecustomize bootstrap directory, or None if ddtrace is not installed."""
    spec = importlib.util.find_spec("ddtrace")
    if spec is None or spec.origin is None:
        return None
    bootstrap = os.path.join(os.path.dirname(spec.origin), "bootstrap")
    return bootstrap if os.path.isdir(bootstrap) else None


def build_instrumented_env(port: int, base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a copy of base_env with tracer env vars injected for Python processes."""
    env = dict(base_env if base_env is not None else os.environ)

    env["DD_TRACE_AGENT_URL"] = f"http://127.0.0.1:{port}"
    env["DD_TRACE_AGENT_HOST"] = "127.0.0.1"
    env["DD_TRACE_AGENT_PORT"] = str(port)
    env["DD_LLMOBS_ENABLED"] = "true"
    env["DD_LLMOBS_AGENTLESS_ENABLED"] = "false"

    bootstrap = _ddtrace_bootstrap_path()
    if bootstrap:
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{bootstrap}{os.pathsep}{existing}" if existing else bootstrap
    else:
        print(
            "[lapdog] ddtrace not installed; Python processes will not be traced. "
            "Install with: pip install 'ddapm-test-agent[ddtrace]'",
            file=sys.stderr,
        )

    return env
