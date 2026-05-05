"""Tracer injection helpers for lapdog: builds an instrumented environment for Python processes."""
import os
import shutil
import subprocess
import sys
from typing import Dict
from typing import List
from typing import Optional


def _ddtrace_bootstrap_path_for(python_path: str) -> Optional[str]:
    """Return ddtrace's bootstrap directory inside the given Python's environment.

    We probe the target Python because the user's app may use a different
    Python than lapdog itself (different version, different venv).
    """
    try:
        result = subprocess.run(
            [
                python_path,
                "-c",
                "import ddtrace, os; "
                "print(os.path.join(os.path.dirname(ddtrace.__file__), 'bootstrap'))",
            ],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
    except (subprocess.SubprocessError, FileNotFoundError):
        return None
    path = result.stdout.strip()
    return path if path and os.path.isdir(path) else None


def build_instrumented_env(
    port: int,
    app_cmd: Optional[List[str]] = None,
    base_env: Optional[Dict[str, str]] = None,
) -> Dict[str, str]:
    """Return a copy of base_env with tracer env vars injected for Python processes."""
    env = dict(base_env if base_env is not None else os.environ)

    env["DD_TRACE_AGENT_URL"] = f"http://127.0.0.1:{port}"
    env["DD_TRACE_AGENT_HOST"] = "127.0.0.1"
    env["DD_TRACE_AGENT_PORT"] = str(port)
    env["DD_LLMOBS_ENABLED"] = "true"
    env["DD_LLMOBS_AGENTLESS_ENABLED"] = "false"

    if not app_cmd:
        return env

    target = shutil.which(app_cmd[0])
    if target is None or not os.path.basename(target).startswith("python"):
        return env

    bootstrap = _ddtrace_bootstrap_path_for(target)
    if bootstrap:
        existing = env.get("PYTHONPATH", "")
        env["PYTHONPATH"] = f"{bootstrap}{os.pathsep}{existing}" if existing else bootstrap
    else:
        print(
            "[lapdog] ddtrace not installed in your Python environment; "
            "processes will not be traced. Install with: pip install ddtrace",
            file=sys.stderr,
        )

    return env
