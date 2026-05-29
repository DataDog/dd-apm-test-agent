"""Claude Code status line script for lapdog.

Claude Code invokes a configured ``statusLine`` command for every render,
passing a JSON blob on stdin that includes the current ``session_id`` (see
https://code.claude.com/docs/en/statusline). We read it and print a single
clickable ``🐶 lapdog`` item that deep-links to this session in the hosted
lapdog dashboard via an OSC-8 terminal hyperlink.

Wired up by ``lapdog claude`` (see ``cli.py``); run standalone as:

    echo '{"session_id": "abc"}' | python -m lapdog.claude_statusline
"""

import json
import sys

from lapdog.constants import session_dashboard_url

# Dog face shown next to "lapdog", matching the pi extension footer status.
DOG_EMOJI = "🐶"
# ANSI styling for the label (purple accent + reset), mirroring the pi
# extension's accent-colored "lapdog" label.
_ACCENT = "\033[38;5;141m"
_RESET = "\033[0m"


def _hyperlink(text: str, url: str) -> str:
    """Wrap text in an OSC-8 terminal hyperlink."""
    return f"\033]8;;{url}\033\\{text}\033]8;;\033\\"


def render(session_id: str) -> str:
    label = f"{_ACCENT}lapdog{_RESET}"
    return f"{DOG_EMOJI} {_hyperlink(label, session_dashboard_url(session_id))}"


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        payload = {}
    session_id = (payload or {}).get("session_id") or ""
    if not session_id:
        # No session yet — print nothing rather than a dead link.
        return 0
    sys.stdout.write(render(session_id))
    return 0


if __name__ == "__main__":
    sys.exit(main())
