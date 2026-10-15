"""Launch a fresh desktop process with an instrumented Codex backend."""

import os
from pathlib import Path
import plistlib
import shlex
import subprocess
import sys
import urllib.parse

from lapdog.cli import codex_setup
from lapdog.paths import LAPDOG_DIR


def launch(cwd: str, port: int, owner: str) -> None:
    if sys.platform != "darwin":
        raise RuntimeError("Desktop process instrumentation currently requires macOS.")
    for directory in (Path("/Applications"), Path.home() / "Applications"):
        for name in ("ChatGPT.app", "Codex.app"):
            bundle = directory / name
            try:
                with (bundle / "Contents/Info.plist").open("rb") as source:
                    info = plistlib.load(source)
                if info.get("CFBundleIdentifier") == "com.openai.codex":
                    break
            except (OSError, ValueError):
                continue
        else:
            continue
        break
    else:
        raise RuntimeError("Codex desktop is not installed. Install it with 'codex app', then quit it and retry.")
    executable = str(bundle / "Contents/MacOS" / info["CFBundleExecutable"])
    processes = subprocess.run(["ps", "-axo", "comm="], capture_output=True, text=True, check=True)
    if executable in processes.stdout.splitlines():
        raise RuntimeError("Quit Codex desktop fully, then rerun 'lapdog codex app' to attach instrumentation.")
    resources = bundle / "Contents/Resources"
    binary = resources / "codex"
    packaged = resources / "codex-cli/bin/codex"
    if packaged.is_file():
        binary = packaged
    if not codex_setup.supported(str(binary)):
        raise RuntimeError("Codex desktop must include Codex CLI 0.124.0 or newer. Update the app.")
    codex_setup.configure(port)
    wrapper = Path(LAPDOG_DIR) / "codex-desktop-backend"
    wrapper.parent.mkdir(parents=True, exist_ok=True)
    command = [
        sys.executable,
        "-m",
        "lapdog.codex_bridge",
        "--binary",
        str(binary),
        "--port",
        str(port),
        "--owner",
        owner,
        "--",
    ]
    wrapper.write_text("#!/bin/sh\nexec " + shlex.join(command) + ' "$@"\n')
    wrapper.chmod(0o700)
    url = "codex://threads/new?" + urllib.parse.urlencode({"path": cwd})
    env = {
        "CODEX_CLI_PATH": str(wrapper),
        "CODEX_APP_SERVER_FORCE_CLI": "1",
        "CODEX_APP_SERVER_USE_LOCAL_DAEMON": "0",
        "LAPDOG_SESSION_TOKEN": owner,
    }
    if os.environ.get("CODEX_HOME"):
        env["CODEX_HOME"] = os.environ["CODEX_HOME"]
    args = ["open", "-a", str(bundle)]
    for key, value in env.items():
        args.extend(["--env", f"{key}={value}"])
    subprocess.run([*args, url], check=True)
    print("[lapdog] Codex desktop capture attached. Review and trust Lapdog session hooks in the app.")
