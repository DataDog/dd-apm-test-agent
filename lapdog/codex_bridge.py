"""Relay desktop app-server JSON-RPC and register this connection's sessions."""

import argparse
import json
import os
import signal
import subprocess
import sys
import threading
from typing import Any
from typing import List
from typing import Set
import uuid

from lapdog.codex_registration import RegistrationClient


class SessionRegistry(RegistrationClient):
    def __init__(self, url: str, owner: str) -> None:
        super().__init__(url, owner)
        self.pending: Set[Any] = set()

    def observe(self, line: bytes, *, outgoing: bool) -> None:
        try:
            message = json.loads(line)
        except ValueError:
            return
        if not isinstance(message, dict):
            return
        if not outgoing and message.get("method") == "thread/started":
            thread = message.get("params", {}).get("thread", {})
            with self.lock:
                parent = thread.get("parentThreadId")
                sid = thread.get("id")
                if not isinstance(parent, str) or parent not in self.sessions or not isinstance(sid, str) or not sid:
                    return
                self.sessions.add(sid)
            self.refresh()
            return
        call_id = message.get("id")
        if not isinstance(call_id, (str, int)):
            return
        changed = False
        with self.lock:
            if outgoing:
                if message.get("method") in ("thread/start", "thread/resume", "thread/fork"):
                    self.pending.add(call_id)
                elif message.get("method") == "turn/start":
                    changed = message.get("params", {}).get("threadId") in self.sessions
            elif call_id in self.pending:
                self.pending.remove(call_id)
                result = message.get("result")
                thread = result.get("thread") if isinstance(result, dict) else None
                sid = thread.get("id") if isinstance(thread, dict) else None
                if isinstance(sid, str) and sid:
                    self.sessions.add(sid)
                    changed = True
        if changed:
            # Register before the app receives the response and can start a turn.
            self.refresh()


def relay(binary: str, args: List[str], port: int, owner: str) -> int:
    registry = SessionRegistry(f"http://localhost:{port}", owner)
    child = subprocess.Popen([binary, *args], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    assert child.stdin is not None and child.stdout is not None
    child_input = child.stdin
    signal.signal(signal.SIGTERM, lambda *_: child.terminate())

    def feed() -> None:
        try:
            for line in sys.stdin.buffer:
                registry.observe(line, outgoing=True)
                child_input.write(line)
                child_input.flush()
        except (BrokenPipeError, OSError):
            pass
        finally:
            child_input.close()

    threading.Thread(target=feed, daemon=True).start()
    try:
        with registry.keepalive():
            for line in child.stdout:
                registry.observe(line, outgoing=False)
                sys.stdout.buffer.write(line)
                sys.stdout.buffer.flush()
            return child.wait()
    finally:
        if child.poll() is None:
            child.terminate()
            child.wait()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--port", required=True, type=int)
    parser.add_argument("--owner", required=True)
    parser.add_argument("args", nargs=argparse.REMAINDER)
    options = parser.parse_args()
    args = options.args[1:] if options.args[:1] == ["--"] else options.args
    if "app-server" not in args or any(arg in args for arg in ("daemon", "proxy", "--help", "--version")):
        os.execv(options.binary, [options.binary, *args])
    sys.exit(relay(options.binary, args, options.port, options.owner + ":" + uuid.uuid4().hex))


if __name__ == "__main__":
    main()
