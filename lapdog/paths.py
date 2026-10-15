"""Fixed filesystem paths for lapdog's working directory."""

import os


LAPDOG_DIR = os.path.expanduser("~/.lapdog")
PID_FILE = os.path.join(LAPDOG_DIR, "lapdog.pid")
LOG_FILE = os.path.join(LAPDOG_DIR, "lapdog.log")
PRICE_FILE = os.path.join(LAPDOG_DIR, "pydantic-genai-pricing-slim.json")
ETAG_FILE = os.path.join(LAPDOG_DIR, "pydantic-genai-pricing-slim.etag")
