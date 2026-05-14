"""Fixed filesystem paths for lapdog's working directory."""

import os

LAPDOG_DIR = os.path.expanduser("~/.lapdog")
PID_FILE = os.path.join(LAPDOG_DIR, "lapdog.pid")
LOG_FILE = os.path.join(LAPDOG_DIR, "lapdog.log")
CODEX_CURSOR_FILE = os.path.join(LAPDOG_DIR, "codex-cursor.json")
