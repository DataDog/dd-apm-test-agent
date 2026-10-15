"""Forward Codex hooks and incremental LLM history without a watcher process.

Run as ``python -m lapdog.codex_hook --url URL``. Cursor state lives in the
collector, so restarting Lapdog causes a safe replay instead of skipped data.
"""

import argparse
import datetime
import json
import os
from pathlib import Path
import sys
from typing import Any
from typing import Dict
from typing import Iterator
from typing import List
from typing import Optional
from typing import Tuple
import urllib.error
import urllib.parse
import urllib.request
import uuid


EVENTS = (
    "SessionStart",
    "SessionEnd",
    "UserPromptSubmit",
    "Stop",
    "Interrupt",
    "PreToolUse",
    "PostToolUse",
    "PermissionRequest",
    "PreCompact",
    "PostCompact",
    "SubagentStart",
    "SubagentStop",
)


CHUNK_BYTES = 4 * 1024 * 1024


def read_session_names(path: Path) -> Dict[str, str]:
    """Read complete name records, including renames, from Codex's index."""
    names = {}
    try:
        with path.open(encoding="utf-8", errors="replace") as source:
            for line in source:
                if not line.endswith("\n"):
                    break
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if isinstance(entry, dict):
                    sid, name = entry.get("id"), entry.get("thread_name")
                    if isinstance(sid, str) and isinstance(name, str) and name.strip():
                        names[sid] = name.strip()
    except OSError:
        pass  # Titles are optional.
    return names


def request(url: str, body: Any = None) -> Dict[str, Any]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as response:
        result = json.load(response)
    if not isinstance(result, dict):
        raise ValueError("unexpected collector response")
    return result


def transcript_identity(path: Path, fallback: str) -> str:
    with path.open("rb") as source:
        meta = json.loads(source.readline())
    if meta.get("type") == "session_meta":
        return str(meta.get("payload", {}).get("id") or fallback)
    return fallback


def read_chunk(path: Path, offset: int) -> Tuple[List[Dict[str, Any]], int]:
    records = []
    with path.open("rb") as source:
        source.seek(offset)
        end = offset
        while source.tell() - offset < CHUNK_BYTES:
            line = source.readline()
            if not line or not line.endswith(b"\n"):
                break  # Leave a partial record for the next hook.
            record = json.loads(line)
            if isinstance(record, dict):
                records.append(record)
            end = source.tell()
    return records, end


def send_transcript(
    url: str,
    path: Path,
    fallback: str,
    *,
    initial_context: bool = False,
    turn_id: Optional[str] = None,
    capture_session_id: Optional[str] = None,
) -> str:
    sid = transcript_identity(path, fallback)
    query = urllib.parse.urlencode({"path": str(path)})
    # Competing hook processes use optimistic cursor checks. A conflict rereads
    # the remaining bytes; no persistent locks, copied transcripts, or poll loop.
    replay = None
    for _ in range(30):
        offset = request(url + "/codex/hooks/cursor?" + query)["offset"]
        if replay is None:
            replay = offset == 0
        records, end = read_chunk(path, offset)
        if not records:
            return sid
        try:
            request(
                url + "/codex/hooks/native",
                {
                    "session_id": sid,
                    "capture_session_id": capture_session_id,
                    "path": str(path),
                    "offset": offset,
                    "end_offset": end,
                    "backfill": replay and not initial_context,
                    "initial_context": replay and initial_context,
                    "capture_turn_id": turn_id,
                    "records": records,
                    "proxy_session_key": os.environ.get("LAPDOG_SESSION_TOKEN"),
                },
            )
        except urllib.error.HTTPError as exc:
            if exc.code != 409:
                raise
            continue
    raise RuntimeError("transcript capture could not catch up; next hook will retry")


def review_transcripts(path: Path, sid: str) -> Iterator[Path]:
    """Find reviewer threads associated with this session, not unrelated chats."""
    for candidate in path.parent.glob("*.jsonl"):
        try:
            with candidate.open("rb") as source:
                meta = json.loads(source.readline()).get("payload", {})
            if meta.get("thread_source") == "guardian_review" and meta.get("parent_thread_id") == sid:
                yield candidate
        except (OSError, ValueError, AttributeError):
            continue


def forward(url: str, hook: Dict[str, Any]) -> None:
    hook = dict(hook)
    hook["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    sid = str(hook.get("session_id") or "")
    if not sid:
        raise ValueError("hook has no session_id")
    capture_session_id = sid
    query = urllib.parse.urlencode(
        {
            "session_id": sid,
            "pid": os.getpid(),
            "path": hook.get("transcript_path") or "",
            "turn_id": hook.get("turn_id") or "",
        }
    )
    if not request(url + "/codex/hooks/registrations?" + query).get("registered"):
        return
    if hook.get("hook_event_name") == "SubagentStart" and hook.get("agent_id"):
        request(url + "/codex/hooks/registrations", {"parent_session_id": sid, "session_ids": [hook["agent_id"]]})
    try:
        transcript = hook.get("transcript_path")
        if transcript and Path(transcript).is_file():
            path = Path(transcript)
            sid = send_transcript(
                url, path, sid, initial_context=True, turn_id=hook.get("turn_id"), capture_session_id=capture_session_id
            )
            if hook.get("hook_event_name") in ("PostToolUse", "Stop", "SessionEnd"):
                for review in review_transcripts(path, sid):
                    send_transcript(url, review, sid, capture_session_id=capture_session_id)
        child = hook.get("agent_transcript_path")
        if child and Path(child).is_file():
            send_transcript(url, Path(child), str(hook.get("agent_id") or sid), capture_session_id=capture_session_id)
    except (OSError, ValueError, RuntimeError) as exc:
        print(f"[lapdog] Codex transcript supplement failed: {exc}", file=sys.stderr)
    home = Path(os.environ.get("CODEX_HOME", str(Path.home() / ".codex")))
    name = read_session_names(home / "session_index.jsonl").get(sid)
    body = {
        "records": [{"type": "event_msg", "payload": {"type": "session_name", "name": name}}] if name else [],
        "session_id": sid,
        "capture_session_id": capture_session_id,
        "event_id": str(uuid.uuid4()),
        "hook": hook,
        "proxy_session_key": os.environ.get("LAPDOG_SESSION_TOKEN"),
    }
    try:
        request(url + "/codex/hooks/native", body)
    except OSError:
        request(url + "/codex/hooks/native", body)  # Same ID makes a lost HTTP reply safe.


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True)
    parser.add_argument("--capture", action="store_true")
    args = parser.parse_args()
    try:
        # A shared Codex daemon can retain LAPDOG_URL from an older launch.
        # Use the collector explicitly configured in this hook's command.
        # Old global registrations lack the capture flag. Leave them inert even if
        # an already-running Codex process still has those commands cached.
        if args.capture:
            forward(args.url.rstrip("/"), json.load(sys.stdin))
    except (OSError, ValueError, RuntimeError) as exc:
        # Capture must never approve, deny, or modify the user's operation.
        print(f"[lapdog] Codex capture failed: {exc}", file=sys.stderr)
    # Stop/SubagentStop require JSON on successful exit; {} is advisory only.
    print("{}")


if __name__ == "__main__":
    main()
