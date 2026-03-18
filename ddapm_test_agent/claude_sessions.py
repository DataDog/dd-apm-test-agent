"""Claude Code Session Scanner.

Reads Claude Code session files from ~/.claude/projects/ and converts them
to Event Platform events so they can be displayed in the Sessions view.
"""

from datetime import datetime
import json
import logging
import os
import time
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .claude_hooks import ClaudeHooksAPI

log = logging.getLogger(__name__)

# Only read first/last N lines of each JSONL file for performance
_HEAD_LINES = 20
_TAIL_LINES = 20


def _read_head_tail(filepath: str, head: int = _HEAD_LINES, tail: int = _TAIL_LINES) -> List[str]:
    """Read the first `head` and last `tail` lines of a file efficiently."""
    lines: List[str] = []
    try:
        with open(filepath, "r") as f:
            all_lines = f.readlines()
    except Exception:
        return []
    if len(all_lines) <= head + tail:
        return [line.rstrip("\n") for line in all_lines]
    head_lines = [line.rstrip("\n") for line in all_lines[:head]]
    tail_lines = [line.rstrip("\n") for line in all_lines[-tail:]]
    lines = head_lines + tail_lines
    return lines


def _parse_jsonl_lines(lines: List[str]) -> List[Dict[str, Any]]:
    """Parse JSONL lines into dicts, skipping invalid ones."""
    entries: List[Dict[str, Any]] = []
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def _extract_first_user_message(entries: List[Dict[str, Any]]) -> str:
    """Extract the first user message text from parsed JSONL entries."""
    for entry in entries:
        if entry.get("type") != "user":
            continue
        content = entry.get("message", {}).get("content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    return block.get("text", "")
                if isinstance(block, str):
                    return block
    return ""


def _count_user_turns(filepath: str) -> int:
    """Count lines with type=user in the entire file (lightweight line scan)."""
    count = 0
    try:
        with open(filepath, "r") as f:
            for line in f:
                if '"type":"user"' in line or '"type": "user"' in line:
                    # Quick check - also verify it's not a tool_result
                    if '"tool_result"' not in line:
                        count += 1
    except Exception:
        pass
    return count


def _dir_name_to_project_path(dir_name: str) -> str:
    """Convert directory name like -Users-kyle-dd to /Users/kyle/dd."""
    if dir_name.startswith("-"):
        return "/" + dir_name[1:].replace("-", "/")
    return dir_name.replace("-", "/")


def scan_all_sessions(claude_dir: str = "~/.claude") -> List[Dict[str, Any]]:
    """Scan all Claude Code session files and return session summaries.

    Walks ~/.claude/projects/*/ for *.jsonl files (top-level only).
    """
    claude_dir = os.path.expanduser(claude_dir)
    projects_dir = os.path.join(claude_dir, "projects")
    if not os.path.isdir(projects_dir):
        return []

    sessions: List[Dict[str, Any]] = []

    try:
        project_dirs = os.listdir(projects_dir)
    except OSError:
        return []

    for project_name in project_dirs:
        project_path = os.path.join(projects_dir, project_name)
        if not os.path.isdir(project_path):
            continue

        try:
            files = os.listdir(project_path)
        except OSError:
            continue

        for filename in files:
            if not filename.endswith(".jsonl"):
                continue
            filepath = os.path.join(project_path, filename)
            if not os.path.isfile(filepath):
                continue

            session_id = filename[:-6]  # strip .jsonl

            try:
                session = _parse_session_file(filepath, session_id, project_name)
                if session:
                    sessions.append(session)
            except Exception as e:
                log.debug("Failed to parse session file %s: %s", filepath, e)

    return sessions


def _parse_session_file(filepath: str, session_id: str, project_name: str) -> Optional[Dict[str, Any]]:
    """Parse a single session JSONL file and return a session summary dict."""
    lines = _read_head_tail(filepath)
    if not lines:
        return None

    entries = _parse_jsonl_lines(lines)
    if not entries:
        return None

    # Extract metadata from entries
    first_input = ""
    start_timestamp = ""
    end_timestamp = ""
    model = ""
    cwd = ""
    git_branch = ""
    version = ""
    slug = ""
    has_error = False
    conversation_title = ""

    for entry in entries:
        entry_type = entry.get("type", "")

        # Get session metadata from any entry that has it
        if not start_timestamp and entry.get("timestamp"):
            start_timestamp = entry["timestamp"]
        if not cwd and entry.get("cwd"):
            cwd = entry["cwd"]
        if not git_branch and entry.get("gitBranch"):
            git_branch = entry["gitBranch"]
        if not version and entry.get("version"):
            version = entry["version"]
        if not slug and entry.get("slug"):
            slug = entry["slug"]

        # Check for sessionId match
        entry_session_id = entry.get("sessionId", "")
        if entry_session_id and entry_session_id != session_id:
            # This is a subagent file or mismatched - skip
            pass

        # Extract model from assistant messages
        if entry_type == "assistant":
            msg_model = entry.get("message", {}).get("model", "")
            if msg_model:
                model = msg_model

        # Track last timestamp
        if entry.get("timestamp"):
            end_timestamp = entry["timestamp"]

    # Extract first user message
    first_input = _extract_first_user_message(entries)
    if not first_input:
        return None  # Skip sessions with no user input

    # Count turns
    num_turns = _count_user_turns(filepath)

    # Compute duration from timestamps
    start_ms = 0
    end_ms = 0
    if start_timestamp:
        try:
            dt = datetime.fromisoformat(start_timestamp.replace("Z", "+00:00"))
            start_ms = int(dt.timestamp() * 1000)
        except (ValueError, TypeError):
            pass
    if end_timestamp:
        try:
            dt = datetime.fromisoformat(end_timestamp.replace("Z", "+00:00"))
            end_ms = int(dt.timestamp() * 1000)
        except (ValueError, TypeError):
            pass

    duration_ns = (end_ms - start_ms) * 1_000_000 if end_ms > start_ms else 0

    project = _dir_name_to_project_path(project_name)

    return {
        "session_id": session_id,
        "first_input": first_input,
        "status": "ok",
        "start_ms": start_ms,
        "end_ms": end_ms,
        "duration_ns": duration_ns,
        "model": model,
        "num_turns": num_turns,
        "project": project,
        "cwd": cwd,
        "git_branch": git_branch,
        "version": version,
        "slug": slug,
        "has_error": has_error,
        "conversation_title": conversation_title,
    }


def enrich_with_hook_data(sessions: List[Dict[str, Any]], hooks_api: "ClaudeHooksAPI") -> List[Dict[str, Any]]:
    """Enrich session data with live state from the hooks API."""
    for session in sessions:
        sid = session["session_id"]
        hook_state = hooks_api._sessions.get(sid)
        if hook_state:
            if not hook_state.root_span_emitted:
                session["status"] = "active"
            # Check for error spans in this session
            for span in hooks_api._assembled_spans:
                if span.get("session_id") == sid and span.get("status") == "error":
                    session["has_error"] = True
                    if session["status"] != "active":
                        session["status"] = "error"
                    break
            # Use conversation title if available
            if hook_state.conversation_title:
                session["conversation_title"] = hook_state.conversation_title
    return sessions


def sessions_to_event_platform_events(sessions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert session summaries to Event Platform event format.

    Matches the shape produced by build_event_platform_list_response.
    """
    spans: List[Dict[str, Any]] = []
    for session in sessions:
        session_id = session["session_id"]
        first_input = session.get("first_input", "")
        status = session.get("status", "ok")
        start_ms = session.get("start_ms", 0)
        end_ms = session.get("end_ms", 0)
        duration_ns = session.get("duration_ns", 0)
        model = session.get("model", "")
        num_turns = session.get("num_turns", 0)
        project = session.get("project", "")
        cwd = session.get("cwd", "")
        slug = session.get("slug", "")
        name = session.get("conversation_title") or (first_input[:80] + "..." if len(first_input) > 80 else first_input)

        # Build a span-like dict that build_event_platform_list_response can consume
        span: Dict[str, Any] = {
            "span_id": session_id,
            "trace_id": session_id,
            "session_id": session_id,
            "parent_id": "undefined",
            "name": name,
            "status": status,
            "start_ns": start_ms * 1_000_000,
            "end_ns": end_ms * 1_000_000,
            "duration": duration_ns,
            "ml_app": "claude-code",
            "service": "claude-code",
            "env": "local",
            "tags": [
                "ml_app:claude-code",
                f"session_id:{session_id}",
                "service:claude-code",
                "env:local",
                "source:claude-code-sessions",
                f"project:{project}",
                f"cwd:{cwd}",
                f"slug:{slug}",
            ],
            "meta": {
                "span": {"kind": "session"},
                "input": {"value": first_input},
                "output": {},
                "model_name": model,
                "metadata": {
                    "project": project,
                    "cwd": cwd,
                    "slug": slug,
                },
            },
            "metrics": {
                "num_turns": num_turns,
            },
            "_event_type": "session",
        }
        spans.append(span)

    return spans


class SessionCache:
    """Cache for session scan results with TTL."""

    def __init__(self, ttl_seconds: float = 5.0) -> None:
        self._ttl = ttl_seconds
        self._cached_sessions: List[Dict[str, Any]] = []
        self._last_scan: float = 0.0
        self._claude_dir: str = "~/.claude"

    def get_sessions(self, claude_dir: str = "~/.claude") -> List[Dict[str, Any]]:
        """Get sessions, rescanning if cache is stale."""
        now = time.time()
        if now - self._last_scan > self._ttl or claude_dir != self._claude_dir:
            self._claude_dir = claude_dir
            self._cached_sessions = scan_all_sessions(claude_dir)
            self._last_scan = now
        return self._cached_sessions
