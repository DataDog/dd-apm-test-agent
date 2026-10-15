"""Keep terminal and desktop capture registrations alive until their launch exits."""

from contextlib import contextmanager
import sys
import threading
from typing import Any
from typing import Iterator
from typing import Set

from lapdog.codex_hook import request


class RegistrationClient:
    def __init__(self, url: str, owner: str, **details: Any) -> None:
        self.url = url + "/codex/hooks/registrations"
        self.owner = owner
        self.details = details
        self.sessions: Set[str] = set()
        self.lock = threading.Lock()
        self.closed = False

    def refresh(self, *, close: bool = False) -> None:
        with self.lock:
            if self.closed:
                return
            self.closed = close
            body = {"owner": self.owner, "session_ids": [] if close else sorted(self.sessions)}
            if not close:
                body.update(self.details)
            try:
                request(self.url, body)
            except (OSError, ValueError) as exc:
                print(f"[lapdog] Codex registration failed: {exc}", file=sys.stderr)

    @contextmanager
    def keepalive(self) -> Iterator[None]:
        stopped = threading.Event()

        def heartbeat() -> None:
            while not stopped.wait(15):
                self.refresh()

        self.refresh()
        worker = threading.Thread(target=heartbeat, daemon=True)
        worker.start()
        try:
            yield
        finally:
            stopped.set()
            worker.join(timeout=6)
            self.refresh(close=True)
