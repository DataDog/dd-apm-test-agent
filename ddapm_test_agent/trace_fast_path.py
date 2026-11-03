"""Opt-in fast path for trace ingestion and ``/test/session/traces`` that does not change behaviour.

Enabled with ``--enable-trace-fast-path`` (``ENABLE_TRACE_FAST_PATH=true``). Two parts:

- Queries: each stored trace request is rendered to JSON once and cached, instead of being
  decoded and serialized again on every ``/test/session/traces`` call. Spans are cached as the
  exact bytes ``json.dumps`` produces for them inside the session response.
- Ingestion (needs the optional ``_native`` extension): v0.4 msgpack payloads are validated and
  transcoded to JSON in C, in a worker thread while the request body is being stored. The result is only used when the extension can show that the Python
  code path would accept the payload without raising or logging; otherwise the request is
  handled by the Python code path unchanged.
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor
import json
import os
from typing import Any
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import msgpack

from .trace import Trace

try:
    from . import _native
except ImportError:  # pure-Python install: queries are still cached, ingestion is not native
    _native = None  # type: ignore[assignment]


# The extension replicates the msgpack>=1.0 defaults that trace.decode_v04 relies on
# (raw=False, strict_map_key=True).
NATIVE_AVAILABLE = _native is not None and msgpack.version >= (1, 0, 0)

# The extension proves that pprint_trace() cannot raise for this format only.
NATIVE_LOG_SPAN_FMT = "[{name}]"

# A run of consecutive spans with the same trace_id, rendered as ", ".join(json.dumps(span)).
Fragments = List[Tuple[Any, bytes]]


def _fragments(res: Optional[Tuple[bytes, List[Tuple[int, int, int]]]]) -> Optional[Fragments]:
    if res is None:
        return None
    body, runs = res
    return [(trace_id, body[start:end]) for trace_id, start, end in runs]


def transcode_v04(data: bytes) -> Optional[Fragments]:
    """Return the payload's cached JSON, or None if only the Python path may handle it."""
    assert _native is not None
    try:
        return _fragments(_native.transcode_v04(data))
    except Exception:
        return None


_pool: Optional[ThreadPoolExecutor] = None


def _executor() -> ThreadPoolExecutor:
    global _pool
    if _pool is None:
        _pool = ThreadPoolExecutor(max_workers=min(8, os.cpu_count() or 1), thread_name_prefix="ddapm-trace-fast-path")
    return _pool


async def transcode_in_worker(transcode: Callable[[bytes], Optional[Fragments]], data: bytes) -> Optional[Fragments]:
    """Run a transcode in a worker thread; the extension releases the GIL while it works."""
    try:
        return await asyncio.get_running_loop().run_in_executor(_executor(), transcode, data)
    except asyncio.CancelledError:
        raise
    except Exception:
        return None


def fragments_from_traces(traces: List[Trace]) -> Fragments:
    """Render decoded traces exactly as json.dumps renders them inside the session list."""
    frags: Fragments = []
    run: List[Any] = []
    run_id: Any = None
    for trace in traces:
        for span in trace:
            trace_id = span["trace_id"]
            if run and trace_id != run_id:
                frags.append((run_id, json.dumps(run)[1:-1].encode()))
                run = []
            run_id = trace_id
            run.append(span)
    if run:
        frags.append((run_id, json.dumps(run)[1:-1].encode()))
    return frags


def session_traces_body(fragment_lists: List[Fragments]) -> bytes:
    """Group fragments by trace_id in first-seen order, like Agent._traces_by_session."""
    by_trace: Dict[Any, List[bytes]] = {}
    for frags in fragment_lists:
        for trace_id, frag in frags:
            by_trace.setdefault(trace_id, []).append(frag)
    return b"[" + b", ".join(b"[" + b", ".join(fs) + b"]" for fs in by_trace.values()) + b"]"
