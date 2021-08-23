from typing import List

from .trace import Span
from .trace import Trace
from .trace import bfs_order
from .trace import root_span


def _span_similarity(s1: Span, s2: Span) -> int:
    score = 0
    for key in ["name", "service", "type", "error", "resource"]:
        if (
            (key not in s1 and key in s2)
            or (key in s2 and key not in s1)
            or s1[key] != s2[key]
        ):
            score -= 1

    s1_meta = s1.get("meta", {})
    s2_meta = s2.get("meta", {})
    for key in set(s1_meta.keys()) | set(s2_meta.keys()):
        if (
            (key not in s1_meta and key in s2_meta)
            or (key in s2_meta and key not in s1_meta)
            or s1_meta[key] != s2_meta[key]
        ):
            score -= 1

    s1_metrics = s1.get("metrics", {})
    s2_metrics = s2.get("metrics", {})
    for key in set(s1_metrics.keys()) | set(s2_metrics.keys()):
        if (
            (key not in s1_metrics and key in s2_metrics)
            or (key in s2_metrics and key not in s1_metrics)
            or s1_metrics[key] != s2_metrics[key]
        ):
            score -= 1
    return score


def _trace_similarity(t1: Trace, t2: Trace) -> int:
    score = 0
    score -= abs(len(t1) - len(t2))
    score += _span_similarity(root_span(t1), root_span(t2))
    return score


def _normalize_trace(trace: Trace, trace_id: int) -> Trace:
    normed_trace = list(bfs_order(trace))
    for span in trace:
        span["trace_id"] = trace_id
        normed_trace.append(span)
    return sorted(normed_trace, key=lambda s: s["start"])


def _normalize_traces(traces: List[Trace]) -> List[Trace]:
    normed_traces = []
    for i, trace in enumerate(traces):
        normed_traces.append(_normalize_trace(trace, i))
    return normed_traces


def snapshot(expected_traces: List[Trace], received_traces: List[Trace]) -> None:
    pass


def generate_snapshot(received_traces: List[Trace]) -> List[Trace]:
    return _normalize_traces(received_traces)


class Snapshot:
    def __init__(
        self, expected_traces: List[Trace], received_traces: List[Trace]
    ) -> None:
        pass

    def _diff_traces(self):
        pass

    def _match_traces(self):
        pass

    def snapshot(self) -> None:
        self._match_traces()
