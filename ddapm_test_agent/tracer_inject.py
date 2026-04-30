"""Tracer injection helpers for lapdog: builds an instrumented environment for Python and Node.js processes."""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from typing import Dict
from typing import Optional
from typing import Tuple

from ddapm_test_agent.lapdog_paths import LAPDOG_DIR
from ddapm_test_agent.lapdog_paths import NODE_MODULES_DIR


def _ddtrace_bootstrap_path() -> Optional[str]:
    """Return the ddtrace sitecustomize bootstrap directory, or None if ddtrace is not installed."""
    spec = importlib.util.find_spec("ddtrace")
    if spec is None or spec.origin is None:
        return None
    bootstrap = os.path.join(os.path.dirname(spec.origin), "bootstrap")
    return bootstrap if os.path.isdir(bootstrap) else None


def _dd_trace_installed() -> bool:
    return os.path.isdir(os.path.join(NODE_MODULES_DIR, "dd-trace"))


def _node_major_minor() -> Optional[Tuple[int, int]]:
    node = shutil.which("node")
    if not node:
        return None
    try:
        out = subprocess.check_output([node, "--version"], text=True).strip()  # e.g. "v20.11.0"
        parts = out.lstrip("v").split(".")
        return (int(parts[0]), int(parts[1]))
    except Exception:
        return None


def _node_options_flag() -> str:
    """Return the appropriate dd-trace NODE_OPTIONS flag for the installed Node.js version.

    Uses absolute paths because NODE_PATH is not respected by ESM --import resolution.
    """
    ver = _node_major_minor()
    # --import + initialize.mjs requires Node 20.6+ for stable ESM support
    if ver is not None and ver >= (20, 6):
        return f"--import {NODE_MODULES_DIR}/dd-trace/initialize.mjs"
    return f"--require {NODE_MODULES_DIR}/dd-trace/init"


def build_instrumented_env(port: int, base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    """Return a copy of base_env with tracer env vars injected for both Python and Node.js.

    Sets PYTHONPATH for ddtrace (via sitecustomize) and NODE_OPTIONS+NODE_PATH for dd-trace.
    Both are set unconditionally so that any child process — regardless of runtime — picks up
    the right instrumentation. Warns but does not fail when a tracer is not installed.
    """
    env = dict(base_env if base_env is not None else os.environ)

    env["DD_TRACE_AGENT_URL"] = f"http://127.0.0.1:{port}"
    env["DD_TRACE_AGENT_HOST"] = "127.0.0.1"
    env["DD_TRACE_AGENT_PORT"] = str(port)
    env["DD_LLMOBS_ENABLED"] = "true"
    env["DD_LLMOBS_AGENTLESS_ENABLED"] = "false"

    # Python: prepend ddtrace's bootstrap dir to PYTHONPATH so sitecustomize.py is imported
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

    # Node.js: inject dd-trace via NODE_OPTIONS using absolute path (NODE_PATH is ignored by ESM --import)
    if not _dd_trace_installed():
        install_node_tracer(required=False)

    if _dd_trace_installed():
        flag = _node_options_flag()
        existing_opts = env.get("NODE_OPTIONS", "")
        env["NODE_OPTIONS"] = f"{flag} {existing_opts}".strip() if existing_opts else flag
    else:
        print(
            "[lapdog] Skipping Node.js instrumentation (dd-trace could not be installed).",
            file=sys.stderr,
        )

    return env


def install_node_tracer(required: bool = False) -> None:
    """`npm install dd-trace` into ~/.lapdog/node_modules.

    If required is True, exits on failure. Otherwise prints a warning and returns.
    """
    if not shutil.which("npm"):
        msg = "[lapdog] npm not found in PATH; cannot install dd-trace."
        if required:
            # TODO: do we just want to always hard fail?
            print(msg, file=sys.stderr)
            sys.exit(1)
        print(f"{msg} Skipping Node.js instrumentation.", file=sys.stderr)
        return
    os.makedirs(LAPDOG_DIR, exist_ok=True)
    pkg_json = os.path.join(LAPDOG_DIR, "package.json")
    if not os.path.exists(pkg_json):
        with open(pkg_json, "w") as f:
            json.dump({"name": "lapdog-deps", "private": True}, f)
    print("[lapdog] Installing dd-trace to ~/.lapdog/node_modules ...", file=sys.stderr)
    try:
        subprocess.check_call(["npm", "install", "dd-trace"], cwd=LAPDOG_DIR)
    except subprocess.CalledProcessError:
        msg = "[lapdog] dd-trace installation failed."
        if required:
            print(msg, file=sys.stderr)
            sys.exit(1)
        print(f"{msg} Skipping Node.js instrumentation.", file=sys.stderr)
        return
    print("[lapdog] dd-trace installed.", file=sys.stderr)
