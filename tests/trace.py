import os
from random import Random
from typing import Any
from typing import Dict

from dd_apm_test_agent.trace import SPAN_TYPES
from dd_apm_test_agent.trace import Span
from dd_apm_test_agent.trace import Trace
from dd_apm_test_agent.trace import dfs_order
from dd_apm_test_agent.trace import v04_verify_span


# Fix the seed for deterministic results
_random = Random(1234)


_dictionaries = ["/usr/share/dict/words", "/usr/dict/words"]
for d in _dictionaries:
    if os.path.exists(d):
        with open(d) as f:
            WORDS = f.read().splitlines()
        break
else:
    WORDS = ["red", "blue", "green", "yellow", "orange"]


def span(rnd: Random = _random, **kwargs: Any) -> Span:
    for k in ["name", "resource", "service"]:
        if k not in kwargs:
            kwargs[k] = rnd.choice(WORDS).lower()

    if "type" not in kwargs:
        kwargs["type"] = rnd.choice(SPAN_TYPES)

    for k in ["trace_id", "span_id"]:
        if k not in kwargs:
            kwargs[k] = rnd.randint(0, 2 ** 64)

    # Don't assign a parent id by default
    if "parent_id" not in kwargs:
        kwargs["parent_id"] = None

    if "start" not in kwargs:
        kwargs["start"] = rnd.randint(0, 2 ** 48)

    if "duration" not in kwargs:
        kwargs["duration"] = rnd.randint(100, 10 ** 10)

    if "meta" not in kwargs:
        kwargs["meta"] = {}

    if "metrics" not in kwargs:
        kwargs["metrics"] = {}
    return v04_verify_span(kwargs)


def _prufers_trace(n: int, rnd: Random = _random) -> Trace:
    """Return a randomly generated trace tree with `n` spans.

    https://en.wikipedia.org/wiki/Pr%C3%BCfer_sequence
    """
    a = [rnd.randint(1, n) for _ in range(n - 2)]
    spans = [span(span_id=i) for i in range(1, n + 1)]
    degree: Dict[int, int] = {}
    for s in spans:
        degree[s["span_id"]] = 1
    for i in a:
        degree[i] += 1

    for i in a:
        for s in spans:
            if degree[s["span_id"]] == 1:
                s["parent_id"] = i
                degree[i] -= 1
                degree[s["span_id"]] -= 1
                break

    u = 0
    for s in spans:
        if degree[s["span_id"]] == 1:
            if u == 0:
                u = s["span_id"]
            else:
                s["parent_id"] = u
                break

    # TODO: randomize the span ids?
    return list(dfs_order(spans))


def random_trace(nspans: int, rng: Random = _random) -> Trace:
    # TODO:
    #   represent arbitrary random services (subtrees in spans)
    #   resource names (should only be on service entry)
    #   smarter type (should only be on service entry)
    #   sampling decisions
    #   dd_origin?
    trace_id = rng.randint(0, 2 ** 64)
    t = _prufers_trace(nspans, rng)
    for s in t:
        s["trace_id"] = trace_id
    return t
