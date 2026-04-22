"""Monotonic wall-clock helper used by span emitters.

Windows' ``time.time_ns()`` is backed by ``GetSystemTimePreciseAsFileTime``,
which advertises 100 ns resolution but can return identical values on
back-to-back calls when the underlying clock hasn't ticked. That is enough
to produce zero-duration spans on fast runners, which breaks tests that
assert ``duration > 0`` (see e.g. ``test_claude_steps.py``).

``monotonic_wall_ns()`` guarantees strict monotonicity: each call returns a value
at least one nanosecond greater than the previous one, while staying as
close as possible to wall-clock time. This matches what span consumers
expect (start_ns ordering, non-zero durations) without forcing us to
track ``perf_counter_ns`` alongside every timestamp.
"""

import threading
import time

_lock = threading.Lock()
_last_ns = 0


def monotonic_wall_ns() -> int:
    """Return a strictly monotonic wall-clock nanosecond timestamp."""
    global _last_ns
    with _lock:
        t = time.time_ns()
        if t <= _last_ns:
            t = _last_ns + 1
        _last_ns = t
        return t
