"""Track the git HEAD commit SHA of a repository over wall-clock time.

Lapdog runs the test agent from inside a project directory while a coding agent
edits files and makes commits. This tracker maintains a timeline of
``(observed_at_ns, sha)`` transitions for that repo's HEAD so that each captured
span/trace can be tagged with ``git.commit.sha`` — the commit that was HEAD at
the moment the span started. Because the SHA changes the instant a commit lands,
the tagged value reveals *when commits happen* during a session.

All git access is best-effort: failures never raise and never block ingest.
"""

import bisect
from datetime import datetime
from datetime import timezone
import logging
import os
import subprocess
import threading
import time
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple


log = logging.getLogger(__name__)

_GIT_TIMEOUT = 5.0
_DEFAULT_POLL_INTERVAL = 1.0


def _run_git(repo_dir: str, args: List[str]) -> Optional[str]:
    """Run a git command in ``repo_dir`` and return stripped stdout, or None on failure."""
    try:
        result = subprocess.run(
            ["git", *args],
            capture_output=True,
            text=True,
            cwd=repo_dir,
            timeout=_GIT_TIMEOUT,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    out = result.stdout.strip()
    return out or None


class GitCommitTracker:
    """Maintains a HEAD-SHA-over-time timeline for a single git repository."""

    def __init__(self, repo_dir: str, poll_interval: float = _DEFAULT_POLL_INTERVAL) -> None:
        self._repo_dir = repo_dir
        self._poll_interval = poll_interval
        self._repo_root: Optional[str] = None
        # Sorted-ascending timeline of (observed_at_ns, sha) HEAD transitions.
        self._timeline: List[Tuple[int, str]] = []
        self._lock = threading.Lock()
        self._repository_url: Optional[str] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        # Cache for `git log --before` fallback lookups, keyed on the formatted
        # date string so repeated misses for the same second don't re-spawn git.
        self._before_cache: Dict[str, Optional[str]] = {}

    # -- repo detection -----------------------------------------------------

    def is_git_repo(self) -> bool:
        """Return True if ``repo_dir`` is inside a git work tree."""
        if self._repo_root is not None:
            return True
        root = _run_git(self._repo_dir, ["rev-parse", "--show-toplevel"])
        if root:
            self._repo_root = root
            return True
        return False

    @property
    def repository_url(self) -> Optional[str]:
        """Cached ``remote.origin.url`` for the repo, if configured."""
        if self._repository_url is None and self._repo_root:
            self._repository_url = _run_git(self._repo_root, ["config", "--get", "remote.origin.url"])
        return self._repository_url

    # -- lifecycle ----------------------------------------------------------

    def start(self) -> None:
        """Resolve the repo, take an initial HEAD observation, and start polling."""
        if not self.is_git_repo():
            log.info("GitCommitTracker: %s is not a git repository; tagging disabled", self._repo_dir)
            return
        # Prime repository_url cache and record the current HEAD up front so spans
        # that arrive before the first poll tick are still taggable.
        _ = self.repository_url
        self._observe()
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._poll_loop, name="git-commit-tracker", daemon=True)
        self._thread.start()
        log.info("GitCommitTracker: watching HEAD of %s", self._repo_root)

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=_GIT_TIMEOUT)
            self._thread = None

    def _poll_loop(self) -> None:
        while not self._stop.wait(self._poll_interval):
            self._observe()

    def _current_head(self) -> Optional[str]:
        root = self._repo_root or self._repo_dir
        return _run_git(root, ["rev-parse", "HEAD"])

    def _observe(self) -> None:
        """Record the current HEAD SHA if it differs from the last observation."""
        sha = self._current_head()
        if not sha:
            return
        now_ns = time.time_ns()
        with self._lock:
            if self._timeline and self._timeline[-1][1] == sha:
                return
            self._timeline.append((now_ns, sha))

    # -- lookup -------------------------------------------------------------

    def sha_at(self, start_ns: Optional[int]) -> Optional[str]:
        """Return the commit SHA that was HEAD at ``start_ns`` (nanoseconds, UTC epoch).

        Resolution order:
          1. The live timeline — latest observation with ``observed_at <= start_ns``.
          2. ``git log --before`` for spans that predate the first observation.
          3. The earliest known SHA, then the current HEAD.
        """
        if not isinstance(start_ns, (int, float)):
            return self._current_head()
        start_ns = int(start_ns)

        with self._lock:
            timeline = list(self._timeline)

        if timeline and start_ns >= timeline[0][0]:
            # Latest observation at or before start_ns.
            idx = bisect.bisect_right([t for t, _ in timeline], start_ns) - 1
            if idx >= 0:
                return timeline[idx][1]

        # Span predates the watcher's first observation: fall back to commit dates.
        before = self._sha_before(start_ns)
        if before:
            return before
        if timeline:
            return timeline[0][1]
        return self._current_head()

    def _sha_before(self, start_ns: int) -> Optional[str]:
        root = self._repo_root or self._repo_dir
        try:
            dt = datetime.fromtimestamp(start_ns / 1_000_000_000, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
        key = dt.strftime("%Y-%m-%d %H:%M:%S %z")
        if key in self._before_cache:
            return self._before_cache[key]
        sha: Optional[str] = _run_git(root, ["log", "--before", key, "--format=%H", "-1"])
        self._before_cache[key] = sha
        return sha

    def transitions(self) -> List[Tuple[int, str]]:
        """Return a copy of the observed ``(observed_at_ns, sha)`` HEAD transitions."""
        with self._lock:
            return list(self._timeline)


def build_tracker_from_env(lapdog_mode: bool) -> Optional[GitCommitTracker]:
    """Construct a GitCommitTracker from environment, or None when disabled/not a repo.

    Enabled by default in lapdog mode; toggle off with ``LAPDOG_GIT_COMMIT_TAGGING=0``.
    The repo defaults to the test agent's cwd (where ``lapdog start`` was run) and
    can be overridden with ``LAPDOG_GIT_REPO``.
    """
    if not lapdog_mode:
        return None
    toggle = os.environ.get("LAPDOG_GIT_COMMIT_TAGGING", "1").strip().lower()
    if toggle in ("0", "false", "no", "off"):
        return None
    repo_dir = os.environ.get("LAPDOG_GIT_REPO") or os.getcwd()
    tracker = GitCommitTracker(repo_dir)
    if not tracker.is_git_repo():
        log.info("GitCommitTracker: %s is not a git repository; commit tagging disabled", repo_dir)
        return None
    return tracker
