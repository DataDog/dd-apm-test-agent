"""Run the Event Platform API tests against ``lapdog server``'s ClickHouse backend.

The tests are imported from ``test_llmobs_event_platform`` and collected here
with ``agent`` pointing at a ``lapdog server`` app, so both backends answer the
same requests. Tests that need the test agent itself (v0.4 traces, in-memory
internals, test-agent-only routes) are excluded below with the reason.
"""

import pytest

from . import test_llmobs_event_platform as evp
from .test_llmobs_event_platform import llmobs_payload  # noqa: F401


@pytest.fixture
def agent(self_hosted_server):
    return self_hosted_server


_IN_MEMORY_INTERNALS = "reads the in-memory backend directly; covered over HTTP in test_self_host.py"
_V04_TRACES = "v0.4 trace intake is a test-agent feature, not part of lapdog server"
_EPOCH_TIMESTAMPS = "uses 1970 timestamps, which retention drops at ingest"
_EXCLUDED = {
    "test_generic_span_is_priced_after_cache_becomes_available": "spans are priced at ingest, not re-priced per query",
    "test_lapdog_estimates_generic_llm_spans_and_updates": _IN_MEMORY_INTERNALS,
    "test_partial_span_update_keeps_unset_fields": _IN_MEMORY_INTERNALS,
    "test_lapdog_estimates_synthetic_v04_llm_span": _V04_TRACES,
    "test_llmobs_list_dedupes_evp_post_against_meta_struct": _V04_TRACES,
    "test_llmobs_list_merges_evp_and_meta_struct_spans": _V04_TRACES,
    "test_llmobs_list_returns_spans_from_v04_meta_struct": _V04_TRACES,
    "test_llmobs_list_parent_children_cross_page": _EPOCH_TIMESTAMPS,
    # Also: spans are unique per (trace_id, span_id) in ClickHouse, so re-sent copies replace each other.
    "test_llmobs_list_paging_identical_span_keys": _EPOCH_TIMESTAMPS,
}

for _name in dir(evp):
    if _name.startswith("test_") and _name not in _EXCLUDED:
        globals()[_name] = getattr(evp, _name)
