from collections import OrderedDict
from collections import defaultdict
import json
import logging
import operator
import pprint
import textwrap
from typing import Any
from typing import Dict
from typing import List
from typing import OrderedDict as OrderedDictType
from typing import Set
from typing import Tuple
from typing import cast

from .checks import Check
from .checks import CheckTrace
from .trace import Span
from .trace import SpanId
from .trace import TopLevelSpanValue
from .trace import Trace
from .trace import TraceId
from .trace import bfs_order
from .trace import child_map
from .trace import copy_trace
from .trace import root_span


log = logging.getLogger(__name__)


DEFAULT_SNAPSHOT_IGNORES = (
    "span_id,trace_id,parent_id,duration,start,metrics.system.pid,meta.runtime-id"
)


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
    try:
        return (key not in d1 and key not in d2) or cast(bool, d1[key] == d2[key])
    except KeyError:
        return False


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
    normed_trace = copy_trace(list(bfs_order(trace)))
    # Have to start at 1 since 0 is reserved for indicating no parent (i.e. root span)
    span_id = 1

    new_id_map: Dict[SpanId, int] = {}
    for span in normed_trace:
        span["trace_id"] = trace_id
        new_id_map[span["span_id"]] = span_id
        span["span_id"] = span_id
        if span["parent_id"]:
            span["parent_id"] = new_id_map[span["parent_id"]]
        else:
            # Normalize the parent of root spans to be 0.
            span["parent_id"] = 0

        if "meta" not in span:
            span["meta"] = {}
        if "metrics" not in span:
            span["metrics"] = {}
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
            t2_trace_id = t2[0]["trace_id"]
            t2_map[t2_trace_id] = t2
            similarities[t1_trace_id].append((t2_trace_id, _trace_similarity(t1, t2)))

    matches: List[Tuple[Trace, Trace]] = []
    tids_to_match = set(similarities.keys())
    while tids_to_match:
        tid = tids_to_match.pop()
        match_tid, match_score = max(similarities[tid], key=lambda t: t[1])
        matches.append((t1_map[tid], t2_map[match_tid]))

    assert tids_to_match == set(), f"Unmatched traces {tids_to_match}"
    return matches


def _diff_spans(
    s1: Span, s2: Span, ignored: Set[str]
) -> Tuple[List[str], List[str], List[str]]:
    """Return differing attributes between two spans and their meta/metrics maps.

    It is assumed that the spans have passed through preliminary validation
    to ensure all required fields are included.

    >>> from .trace import verify_span, copy_span
    >>> span = verify_span(dict(name="", trace_id=1234, span_id=11, meta={}, metrics={}))
    >>> span2 = copy_span(span)
    >>> span2["resource"] = ""
    >>> _diff_spans(span, span2, set())
    (['resource'], [], [])
    >>> span2["type"] = "web"
    >>> tuple(map(set, _diff_spans(span, span2, set()))) == ({'resource', 'type'}, set(), set())
    True
    >>> span2["meta"]["key"] = "value"
    >>> tuple(map(set, _diff_spans(span, span2, set()))) == ({'resource', 'type'}, {'key'}, set())
    True
    >>> span2["metrics"]["key2"] = 100.0
    >>> tuple(map(set, _diff_spans(span, span2, set()))) == ({'resource', 'type'}, {'key'}, {'key2'})
    True
    >>> _diff_spans(span, span2, set(['metrics.key2', 'meta.key', 'resource', 'type', 'meta.key2']))
    ([], [], [])
    """
    results = []
    s1_no_tags = cast(
        Dict[str, TopLevelSpanValue],
        {k: v for k, v in s1.items() if k not in ("meta", "metrics")},
    )
    s2_no_tags = cast(
        Dict[str, TopLevelSpanValue],
        {k: v for k, v in s2.items() if k not in ("meta", "metrics")},
    )
    for d1, d2, ignored in [
        (s1_no_tags, s2_no_tags, ignored),
        (s1["meta"], s2["meta"], set(i[5:] for i in ignored if i.startswith("meta."))),
        (
            s1["metrics"],
            s2["metrics"],
            set(i[8:] for i in ignored if i.startswith("metrics.")),
        ),
    ]:
        d1 = cast(Dict[str, Any], d1)
        d2 = cast(Dict[str, Any], d2)
        diffs = []
        for k in (set(d1.keys()) | set(d2.keys())) - ignored:
            if not _key_match(d1, d2, k):
                diffs.append(k)
        results.append(diffs)
    return cast(Tuple[List[str], List[str], List[str]], tuple(results))


def _compare_traces(expected: Trace, received: Trace, ignored: Set[str]) -> None:
    """Compare two traces for differences.

    The given traces are assumed to be in BFS order.
    """
    assert len(expected) == len(
        received
    ), f"Number of traces received ({len(received)}) doesn't match expected ({len(expected)})."

    for s_exp, s_rec in zip(expected, received):
        with CheckTrace.add_frame(
            f"snapshot compare of span '{s_exp['name']}' at position {s_exp['span_id']} in trace"
        ) as frame:
            frame.add_item(f"Expected span:\n{pprint.pformat(s_exp)}")
            frame.add_item(f"Received span:\n{pprint.pformat(s_rec)}")
            top_level_diffs, meta_diffs, metrics_diffs = _diff_spans(
                s_exp, s_rec, ignored
            )

            for diffs, diff_type, d_exp, d_rec in [
                (top_level_diffs, "span", s_exp, s_rec),
                (meta_diffs, "meta", s_exp["meta"], s_rec["meta"]),
                (metrics_diffs, "metrics", s_exp["metrics"], s_rec["metrics"]),
            ]:
                for diff_key in diffs:
                    if diff_key not in d_exp:
                        raise AssertionError(
                            f"Span{' ' + diff_type if diff_type != 'span' else ''} value '{diff_key}' in received span but is not in the expected span."
                        )
                    elif diff_key not in d_rec:
                        raise AssertionError(
                            f"Span{' ' + diff_type if diff_type != 'span' else ''} value '{diff_key}' in expected span but is not in the received span."
                        )
                    else:
                        raise AssertionError(
                            f"{diff_type} mismatch on '{diff_key}': got '{d_rec[diff_key]}' which does not match expected '{d_exp[diff_key]}'."
                        )


class SnapshotFailure(Exception):
    pass


class SnapshotCheck(Check):
    def check(self, *args, **kwargs):
        pass


def snapshot(
    expected_traces: List[Trace], received_traces: List[Trace], ignored: List[str]
) -> None:
    normed_expected = _normalize_traces(expected_traces)
    normed_received = _normalize_traces(received_traces)
    matched = _match_traces(normed_expected, normed_received)
    log.debug("Matched traces %r", matched)

    for exp, rec in matched:
        with CheckTrace.add_frame(f"trace ({len(exp)}) spans"):
            _compare_traces(exp, rec, set(ignored))


def _snapshot_trace_str(trace: Trace) -> str:
    cmap = child_map(trace)
    stack: List[Tuple[int, Span]] = [(0, root_span(trace))]
    s = "[\n"
    while stack:
        prefix, span = stack.pop(0)
        for i, child in enumerate(reversed(cmap[span["span_id"]])):
            if i == 0:
                stack.insert(0, (prefix + 3, child))
            else:
                stack.insert(0, (prefix + 3, child))

        def ordered_span(s: Span) -> OrderedDictType[str, str]:
            """Order the span to be more human readable."""
            d = OrderedDict()
            for k in [
                "name",
                "service",
                "resource",
                "trace_id",
                "span_id",
                "parent_id",
                "error",
            ]:
                if k in s:
                    d[k] = s[k]  # type: ignore
            for k in sorted(set(s.keys()) - {"name", "service", "resource"}):
                d[k] = s[k]  # type: ignore

            d["meta"] = OrderedDict(
                sorted(s["meta"].items(), key=operator.itemgetter(0))
            )
            d["metrics"] = OrderedDict(
                sorted(s["metrics"].items(), key=operator.itemgetter(0))
            )
            return d

        s += textwrap.indent(
            json.dumps(ordered_span(span), indent=2), " " * (prefix + 2)
        )
        if stack:
            s += ",\n"
    s += "]"
    return s


def _snapshot_json(traces: List[Trace]) -> str:
    s = "["
    for t in traces:
        s += _snapshot_trace_str(t)
        if t != traces[-1]:
            s += ",\n"
    s += "]\n"
    return s


def generate_snapshot(received_traces: List[Trace]) -> str:
    return _snapshot_json(_normalize_traces(received_traces))
