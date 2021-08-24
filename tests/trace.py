from random import Random
from typing import Dict

from dd_apm_test_agent.trace import SPAN_TYPES
from dd_apm_test_agent.trace import dfs_order
from dd_apm_test_agent.trace import Trace


# Fix the seed for deterministic results
_random = Random(1234)

with open("/usr/share/dict/words") as f:
    WORDS = f.read().splitlines()


def span(rnd: Random = _random, **kwargs):
    for k in ["name", "resource", "service"]:
        if k not in kwargs:
            kwargs[k] = rnd.choice(WORDS).lower()

    if "type" not in kwargs:
        kwargs["type"] = rnd.choice(SPAN_TYPES)

    for k in ["trace_id", "span_id"]:
        if k not in kwargs:
            kwargs[k] = rnd.randint(0, 2**64)

    # Don't assign a parent id by default
    if "parent_id" not in kwargs:
        kwargs["parent_id"] = None

    if "start" not in kwargs:
        kwargs["start"] = rnd.randint(0, 2**48)

    if "duration" not in kwargs:
        kwargs["duration"] = rnd.randint(100, 10**10)

    if "meta" not in kwargs:
        kwargs["meta"] = {}

    if "metrics" not in kwargs:
        kwargs["metrics"] = {}
    return kwargs


def _prufers_trace(n: int, rnd: Random = _random) -> Trace:
    """Return a randomly generated trace tree with `n` spans.

    https://en.wikipedia.org/wiki/Pr%C3%BCfer_sequence
    """
    a = [rnd.randint(1, n) for _ in range(n-2)]
    spans = [span(span_id=i) for i in range(1, n+1)]
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


def trace(nspans: int, rng: Random = _random) -> Trace:
    trace_id = rng.randint(0, 2**64)
    t = _prufers_trace(nspans, rng)
    for s in t:
        s["trace_id"] = trace_id
    return t
