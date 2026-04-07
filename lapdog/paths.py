"""Fixed filesystem paths for lapdog's working directory."""
import os

LAPDOG_DIR = os.path.expanduser("~/.lapdog")
NODE_MODULES_DIR = os.path.join(LAPDOG_DIR, "node_modules")
PID_FILE = os.path.join(LAPDOG_DIR, "lapdog.pid")
LOG_FILE = os.path.join(LAPDOG_DIR, "lapdog.log")
