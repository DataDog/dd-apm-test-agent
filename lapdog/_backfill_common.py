"""Shared helpers for the ``lapdog <source> --backfill`` commands."""

import sys
import time
from typing import Any
from typing import Dict

import requests
from requests.exceptions import ConnectionError as RequestsConnectionError

# Connection-pooled session shared by every backfill module. Mirrors the
# pattern in ``lapdog.codex_watcher`` so a single TCP connection serves all
# the per-record POSTs.
_session = requests.Session()

# (connect_timeout, read_timeout). Read timeout is generous because the
# server may spend hundreds of ms building spans for a large session.
_POST_TIMEOUT = (1.0, 30.0)

# Module-level flag set when lapdog stops responding so callers can stop
# trying further sessions instead of spamming connection-refused errors.
_lapdog_dead = False


class LapdogDead(Exception):
    """Raised when the local lapdog stops responding mid-backfill."""


def _is_lapdog_alive(lapdog_url: str) -> bool:
    """Probe ``/info`` with a short timeout."""
    try:
        r = _session.get(f"{lapdog_url.rstrip('/')}/info", timeout=(0.5, 1.5))
        return r.status_code == 200
    except Exception:
        return False


def preflight_endpoint(lapdog_url: str, path: str) -> bool:
    """Verify the lapdog at ``lapdog_url`` actually has ``path`` registered.

    Older lapdog processes started before this version don't have the new
    ``/claude/hooks/backfill_session`` and ``/pi/hooks/backfill_session``
    routes. Without this check, the client would POST every session and get
    404 back, with no clear indication of what's wrong. Here we send one
    deliberately-empty POST: if we get 400 ("session_id and entries
    required") the route is wired up; if we get 404, it isn't; on other
    statuses (or transport errors) we bail with a clear message.

    Returns True if the endpoint is present and usable.
    """
    url = f"{lapdog_url.rstrip('/')}{path}"
    try:
        response = _session.post(url, json={}, timeout=(1.0, 5.0))
    except Exception as exc:
        print(
            f"lapdog backfill: cannot reach {url}: {exc}. " f"Is lapdog running? Try 'lapdog start'.",
            file=sys.stderr,
            flush=True,
        )
        return False
    if response.status_code == 404:
        print(
            f"lapdog backfill: {path} not found on the running lapdog. "
            f"This version of lapdog is older than the --backfill feature. "
            f"Restart lapdog ('lapdog stop && lapdog start') to pick up the new endpoint.",
            file=sys.stderr,
            flush=True,
        )
        return False
    if response.status_code == 400:
        # Expected: handler rejected the empty body. Route exists.
        return True
    if 200 <= response.status_code < 300:
        # Handler accepted the empty body — unusual but the route exists.
        return True
    print(
        f"lapdog backfill: preflight to {url} returned status={response.status_code}; aborting.",
        file=sys.stderr,
        flush=True,
    )
    return False


def post_event(lapdog_url: str, path: str, body: Dict[str, Any]) -> bool:
    """POST ``body`` as JSON to ``{lapdog_url}{path}``.

    Returns True on a 2xx response. Returns False on application errors
    (4xx/5xx). On a transport failure (connection refused, broken pipe,
    etc.), checks whether the lapdog is still alive: if not, raises
    ``LapdogDead`` so the caller can stop iterating instead of
    spraying hundreds of "connection refused" messages.
    """
    global _lapdog_dead
    if _lapdog_dead:
        raise LapdogDead("lapdog stopped responding")
    url = f"{lapdog_url.rstrip('/')}{path}"
    try:
        response = _session.post(url, json=body, timeout=_POST_TIMEOUT)
    except RequestsConnectionError as exc:
        # Distinguish "lapdog died" from a transient socket hiccup by
        # re-probing /info. If it's truly dead, latch the flag and raise so
        # backfill exits cleanly. Otherwise log and continue.
        # Give the OS a beat to settle the socket state before re-probing.
        time.sleep(0.2)
        if not _is_lapdog_alive(lapdog_url):
            _lapdog_dead = True
            print(
                f"lapdog backfill: lapdog at {lapdog_url} is not responding — aborting backfill. "
                f"Check ~/.lapdog/lapdog.log; restart with 'lapdog start' and re-run.",
                file=sys.stderr,
                flush=True,
            )
            raise LapdogDead(str(exc)) from exc
        print(f"lapdog backfill: transient post failure url={url}: {exc}", file=sys.stderr, flush=True)
        return False
    except Exception as exc:
        print(f"lapdog backfill: post failed url={url}: {exc}", file=sys.stderr, flush=True)
        return False
    if response.status_code >= 400:
        print(
            f"lapdog backfill: post failed status={response.status_code} url={url}",
            file=sys.stderr,
            flush=True,
        )
        return False
    return True
