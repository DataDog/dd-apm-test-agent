"""Unit tests for LLMObs ``meta_struct['_llmobs']`` extraction helpers."""

from ddapm_test_agent.llmobs_trace import LLMOBS_ROOT_PARENT_ID
from ddapm_test_agent.llmobs_trace import LLMOBS_STRUCT_KEY
from ddapm_test_agent.llmobs_trace import build_sdk_span_event
from ddapm_test_agent.llmobs_trace import extract_llmobs_envelopes_from_v04_traces


def _apm_span(**overrides):
    span = {
        "name": "openai.request",
        "span_id": 1234,
        "trace_id": 0xABC,
        "start": 1_700_000_000_000_000_000,
        "duration": 250_000_000,
        "error": 0,
        "meta": {},
    }
    span.update(overrides)
    return span


def _llmobs_data(**overrides):
    data = {
        "trace_id": "11111111111111111111111111111111",
        "parent_id": "00000000000000000000000000000001",
        "name": "openai.chat.completion",
        "meta": {
            "span": {"kind": "llm"},
            "input": {"value": "hi"},
            "output": {"value": "hello"},
            "model_name": "gpt-4",
            "model_provider": "openai",
        },
        "metrics": {"input_tokens": 5, "output_tokens": 7, "total_tokens": 12},
        "tags": {"env": "test", "service": "weblog"},
    }
    data.update(overrides)
    return data


def test_build_sdk_span_event_minimal_payload():
    event = build_sdk_span_event(_llmobs_data(), _apm_span())

    assert event is not None
    assert event["trace_id"] == "11111111111111111111111111111111"
    assert event["span_id"] == "1234"
    assert event["parent_id"] == "00000000000000000000000000000001"
    assert event["name"] == "openai.chat.completion"
    assert event["start_ns"] == 1_700_000_000_000_000_000
    assert event["duration"] == 250_000_000
    assert event["status"] == "ok"
    assert event["meta"]["span"]["kind"] == "llm"
    assert event["metrics"]["total_tokens"] == 12
    # The agent re-adds the proxy-mode ``error`` tag that the SDK appends at EVP-serialization time.
    assert event["tags"] == ["env:test", "error:0", "service:weblog"]
    # _dd.trace_id is the 32-char hex render of the APM trace_id (not the LLMObs trace_id).
    assert event["_dd"]["trace_id"] == "00000000000000000000000000000abc"
    assert event["_dd"]["apm_trace_id"] == "00000000000000000000000000000abc"


def test_build_sdk_span_event_combines_128bit_trace_id_from_dd_p_tid():
    # 128-bit traces carry the low 64 bits in span.trace_id and the high 64 bits in the
    # _dd.p.tid meta tag; the rendered _dd.trace_id must recombine both halves.
    span = _apm_span(trace_id=0xABC, meta={"_dd.p.tid": "640cfde200000000"})
    event = build_sdk_span_event(_llmobs_data(), span)
    assert event["_dd"]["trace_id"] == "640cfde2000000000000000000000abc"
    assert event["_dd"]["apm_trace_id"] == "640cfde2000000000000000000000abc"


def test_build_sdk_span_event_returns_none_when_required_fields_missing():
    assert build_sdk_span_event({"parent_id": "x"}, _apm_span()) is None
    assert build_sdk_span_event(_llmobs_data(), {"name": "no-ids"}) is None
    assert build_sdk_span_event(_llmobs_data(), {"trace_id": 1}) is None


def test_build_sdk_span_event_defaults_parent_id_and_name():
    event = build_sdk_span_event(_llmobs_data(parent_id=None, name=None), _apm_span(name="fallback-name"))
    assert event["parent_id"] == LLMOBS_ROOT_PARENT_ID
    assert event["name"] == "fallback-name"


def test_build_sdk_span_event_error_status_and_optional_fields():
    event = build_sdk_span_event(
        _llmobs_data(
            session_id="sess-1",
            ml_app="my-app",
            config={"experiment_id": "exp-1"},
            span_links=[{"span_id": "abc", "trace_id": "def"}],
        ),
        _apm_span(error=1),
    )
    assert event["status"] == "error"
    assert event["session_id"] == "sess-1"
    # ml_app is never promoted to a top-level field; it only appears inside ``tags``.
    assert "ml_app" not in event
    assert event["config"] == {"experiment_id": "exp-1"}
    assert event["span_links"] == [{"span_id": "abc", "trace_id": "def"}]


def test_build_sdk_span_event_preserves_caller_dd_attrs():
    # Caller-provided _dd values must not be overwritten by the agent-injected ones.
    event = build_sdk_span_event(_llmobs_data(_dd={"scope": "experiments", "extra": "value"}), _apm_span())
    assert event["_dd"]["scope"] == "experiments"
    assert event["_dd"]["extra"] == "value"
    assert event["_dd"]["span_id"] == "1234"


def test_build_sdk_span_event_accepts_list_tags():
    event = build_sdk_span_event(_llmobs_data(tags=["env:test", "version:1"]), _apm_span())
    assert event["tags"] == ["env:test", "error:0", "version:1"]


def test_build_sdk_span_event_injects_error_tags_from_apm_span():
    event = build_sdk_span_event(
        _llmobs_data(),
        _apm_span(error=1, meta={"error.type": "ValueError"}),
    )
    assert "error:1" in event["tags"]
    assert "error_type:ValueError" in event["tags"]


def test_extract_envelopes_only_yields_spans_with_llmobs_struct():
    traces = [
        [
            {**_apm_span(span_id=1), "meta_struct": {LLMOBS_STRUCT_KEY: _llmobs_data()}},
            _apm_span(span_id=2),
            {**_apm_span(span_id=3), "meta_struct": {"appsec": {"foo": "bar"}}},
        ],
        [{**_apm_span(span_id=4, trace_id=0xDEF), "meta_struct": {LLMOBS_STRUCT_KEY: _llmobs_data(trace_id="other")}}],
    ]
    envelopes = extract_llmobs_envelopes_from_v04_traces(traces)

    assert {e["spans"][0]["span_id"] for e in envelopes} == {"1", "4"}


def test_extract_envelopes_match_writer_data_shape():
    span = {**_apm_span(), "meta_struct": {LLMOBS_STRUCT_KEY: _llmobs_data()}}
    env = extract_llmobs_envelopes_from_v04_traces([[span]])[0]
    assert env["_dd.stage"] == "raw"
    assert env["event_type"] == "span"
    assert env["_dd.tracer_version"]
    assert len(env["spans"]) == 1


def test_extract_envelopes_marks_experiments_scope():
    span = {**_apm_span(), "meta_struct": {LLMOBS_STRUCT_KEY: _llmobs_data(_dd={"scope": "experiments"})}}
    assert extract_llmobs_envelopes_from_v04_traces([[span]])[0]["_dd.scope"] == "experiments"


def test_extract_envelopes_skips_malformed_inputs():
    assert extract_llmobs_envelopes_from_v04_traces([]) == []
    assert extract_llmobs_envelopes_from_v04_traces([None]) == []
    assert extract_llmobs_envelopes_from_v04_traces([[None, "not a span"]]) == []
    bad = {**_apm_span(), "meta_struct": {LLMOBS_STRUCT_KEY: "not a dict"}}
    assert extract_llmobs_envelopes_from_v04_traces([[bad]]) == []
