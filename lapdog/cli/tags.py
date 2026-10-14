"""Session tagging."""

import json
import os
import sys
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
import urllib.error
import urllib.request

from lapdog.cli.runtime import _PATH_ROUTABLE_LAUNCHERS


def _post_session_tags(
    lapdog_url: str,
    session_token: str,
    tags: Dict[str, str],
    session_id: Optional[str] = None,
) -> Dict[str, Any]:
    body: Dict[str, Any] = {"tags": tags}
    if session_id:
        body["session_id"] = session_id
    request = urllib.request.Request(
        f"{lapdog_url.rstrip('/')}/lapdog/session/tags",
        data=json.dumps(body).encode(),
        headers={
            "Content-Type": "application/json",
            "X-Lapdog-Session-Token": session_token,
        },
        method="POST",
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(request, timeout=2) as response:
        result = json.loads(response.read())
    if not isinstance(result, dict):
        raise ValueError("Lapdog returned an invalid response")
    return result


def cmd_tags(sub_cmd_args: List[str]) -> None:
    """Add key:value tags to the current instrumented coding-agent session."""
    if len(sub_cmd_args) < 2 or sub_cmd_args[0] != "set":
        print("Usage: lapdog tags set <key:value> [key:value ...]", file=sys.stderr)
        sys.exit(1)

    tags: Dict[str, str] = {}
    for raw_tag in sub_cmd_args[1:]:
        key, separator, value = raw_tag.partition(":")
        key = key.strip()
        value = value.strip()
        if not separator or not key or not value:
            print(f"[lapdog] Invalid tag {raw_tag!r}; expected key:value.", file=sys.stderr)
            sys.exit(1)
        tags[key] = value

    session_token = os.environ.get("LAPDOG_SESSION_TOKEN", "")
    lapdog_url = os.environ.get("LAPDOG_URL", "")
    target_session_id = os.environ.get("CODEX_THREAD_ID") or os.environ.get("PI_SESSION_ID") or None
    if not session_token or not lapdog_url:
        supported_launchers = ", ".join(f"'lapdog {launcher}'" for launcher in _PATH_ROUTABLE_LAUNCHERS)
        print(
            "[lapdog] No instrumented coding-agent session found. "
            f"Run this command from inside a session started with one of: {supported_launchers}.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        result = _post_session_tags(lapdog_url, session_token, tags, session_id=target_session_id)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace").strip()
        print(f"[lapdog] Failed to set session tags: HTTP {exc.code}: {detail}", file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError) as exc:
        print(f"[lapdog] Failed to set session tags: {exc}", file=sys.stderr)
        sys.exit(1)

    formatted_tags = ", ".join(f"{key}:{value}" for key, value in tags.items())
    tagged_session_id = result.get("session_id")
    if tagged_session_id:
        print(f"[lapdog] Tagged coding-agent session {tagged_session_id}: {formatted_tags}")
    else:
        print(f"[lapdog] Queued tags for the current coding-agent session: {formatted_tags}")
