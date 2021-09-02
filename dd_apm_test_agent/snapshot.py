from collections import defaultdict
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Tuple
from typing import cast

from .checks import Check
from .checks import CheckTrace
from .trace import Span
from .trace import SpanId
from .trace import Trace
from .trace import TraceId
from .trace import bfs_order
from .trace import root_span


log = logging.getLogger(__name__)


def _key_match(d1: Dict[str, Any], d2: Dict[str, Any], key: str) -> bool:
    """
    >>> _key_match({"a": 1}, {"a": 2}, "a")
    False
    >>> _key_match({"a": 1}, {"a": 2}, "b")
    True
    >>> _key_match({"a": 2}, {"a": 1}, "a")
    False
    >>> _key_match({"a": 1}, {"a": 1}, "a")
    True
    >>> _key_match({"a": 2}, {"b": 1}, "a")
    False
    >>> _key_match({"b": 2}, {"a": 1}, "a")
    False
    """
    if (key not in d1 and key in d2) or (key not in d2 and key in d1):
        return False
    elif key not in d1 and key not in d2:
        return True
    else:
        return cast(bool, d1[key] == d2[key])


def _span_similarity(s1: Span, s2: Span) -> int:
    score = 0

    for key in ["name", "service", "type", "error", "resource"]:
        if not _key_match(s1, s2, key):  # type: ignore
            score -= 1

    s1_meta = s1.get("meta", {})
    s2_meta = s2.get("meta", {})
    for key in set(s1_meta.keys()) | set(s2_meta.keys()):
        if not _key_match(s1_meta, s2_meta, key):
            score -= 1

    s1_metrics = s1.get("metrics", {})
    s2_metrics = s2.get("metrics", {})
    for key in set(s1_metrics.keys()) | set(s2_metrics.keys()):
        if not _key_match(s1_metrics, s2_metrics, key):
            score -= 1
    return score


def _trace_similarity(t1: Trace, t2: Trace) -> int:
    score = 0
    score -= abs(len(t1) - len(t2))
    score += _span_similarity(root_span(t1), root_span(t2))
    # TODO: also compare child spans? try to match them somehow?
    return score


def _normalize_trace(trace: Trace, trace_id: TraceId) -> Trace:
    normed_trace = list(bfs_order(trace))
    span_id = 0

    new_id_map: Dict[SpanId, int] = {}
    for span in trace:
        span["trace_id"] = trace_id
        new_id_map[span["span_id"]] = span_id
        span["span_id"] = span_id
        if span["parent_id"]:
            span["parent_id"] = new_id_map[span["parent_id"]]
        span_id += 1
    return normed_trace


def _normalize_traces(traces: List[Trace]) -> List[Trace]:
    normed_traces = []
    for i, trace in enumerate(traces):
        normed_traces.append(_normalize_trace(trace, i))
    return normed_traces


def _match_traces(t1s: List[Trace], t2s: List[Trace]) -> List[Tuple[Trace, Trace]]:
    similarities: Dict[TraceId, List[Tuple[TraceId, int]]] = defaultdict(lambda: [])
    t1_map: Dict[TraceId, Trace] = {}
    t2_map: Dict[TraceId, Trace] = {}
    for t1 in t1s:
        t1_trace_id = t1[0]["trace_id"]
        t1_map[t1_trace_id] = t1
        for t2 in t2s:
            t2_trace_id = t1[0]["trace_id"]
            t2_map[t2_trace_id] = t2
            similarities[t1_trace_id].append((t2_trace_id, _trace_similarity(t1, t2)))

    matches: List[Tuple[Trace, Trace]] = []
    tids_to_match = set(similarities.keys())
    while tids_to_match:
        tid = tids_to_match.pop()
        match_tid, match_score = min(similarities[tid], key=lambda t: t[1])
        matches.append((t1_map[tid], t2_map[match_tid]))

    # TODO: check for unmatched traces
    return matches


def _compare(expected: Trace, received: Trace) -> None:
    if len(expected) != len(received):
        raise AssertionError(
            f"Number of traces received ({len(received)}) doesn't match expected ({len(expected)})"
        )


class SnapshotFailure(Exception):
    pass


class SnapshotCheck(Check):
    def check(self, *args, **kwargs):
        pass


def snapshot(expected_traces: List[Trace], received_traces: List[Trace]) -> None:
    normed_expected, normed_received = map(
        _normalize_traces, (expected_traces, received_traces)
    )
    matched = _match_traces(normed_expected, normed_received)
    log.debug("Matched traces %r", matched)

    for exp, rec in matched:
        with CheckTrace.add_frame(f"trace ({len(exp)}) spans"):
            _compare(exp, rec)


def generate_snapshot(received_traces: List[Trace]) -> List[Trace]:
    return _normalize_traces(received_traces)
