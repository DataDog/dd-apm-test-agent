import copy

from aiohttp import web

from ddapm_test_agent.trace_forwarding import TRACE_INTAKE_URLS
from ddapm_test_agent.trace_forwarding import build_v2_trace_payload
from ddapm_test_agent.trace_forwarding import forward_traces_to_v2_intake
from ddapm_test_agent.trace_forwarding import trace_intake_url


def test_trace_intake_url():
    assert trace_intake_url("DATADOGHQ.COM") == ("https://public-trace-http-intake.logs.datadoghq.com/api/v2/spans")
    assert trace_intake_url("us2.ddog-gov.com") == ("https://browser-intake-us2-ddog-gov.com/api/v2/spans")


def test_build_v2_trace_payload_preserves_spans_and_adds_minimal_tags():
    traces = [
        [
            {
                "trace_id": 0xABCDEF,
                "span_id": 1,
                "parent_id": 0,
                "service": "frontend",
                "name": "request",
                "resource": "GET /",
                "start": 10,
                "duration": 20,
                "error": 0,
                "meta": {
                    "_dd.origin": "synthetics",
                    "_dd.p.tid": "1234567890abcdef",
                    "shared": "span",
                },
                "metrics": {"existing": 2},
            },
            {
                "trace_id": 0xABCDEF,
                "span_id": 2,
                "parent_id": 1,
                "service": "frontend",
                "name": "child",
            },
            {
                "trace_id": 0xABCDEF,
                "span_id": 3,
                "parent_id": 1,
                "service": "backend",
                "name": "service entry",
            },
            {
                "trace_id": 0xABCDEF,
                "span_id": 4,
                "parent_id": 999,
                "service": "frontend",
                "name": "partial chunk root",
            },
        ]
    ]
    original = copy.deepcopy(traces)

    payload = build_v2_trace_payload(traces, {"forwarded_by": "test-agent", "shared": "configured"})

    assert traces == original
    spans = payload["traces"][0]["spans"]
    assert spans[0]["trace_id"] == "1234567890abcdef0000000000abcdef"
    assert spans[0]["span_id"] == "0000000000000001"
    assert spans[0]["parent_id"] == "0000000000000000"
    assert spans[0]["meta"] == {
        "_dd.origin": "synthetics",
        "_dd.p.tid": "1234567890abcdef",
        "forwarded_by": "test-agent",
        "shared": "configured",
        "_dd.compute_stats": "1",
    }
    assert spans[0]["metrics"] == {"existing": 2, "_trace_root": 1, "_top_level": 1}
    assert "_top_level" not in spans[1].get("metrics", {})
    assert spans[2]["metrics"]["_top_level"] == 1
    assert spans[3]["metrics"]["_top_level"] == 1
    assert "_trace_root" not in spans[3]["metrics"]
    assert all(span["meta"]["forwarded_by"] == "test-agent" for span in spans)
    assert all(span["meta"]["shared"] == "configured" for span in spans)
    assert all("_dd.origin" not in span.get("meta", {}) for span in spans[1:])


async def test_forward_traces_to_v2_intake(aiohttp_server, monkeypatch):
    captured = {}

    async def receive(request):
        captured["headers"] = request.headers
        captured["payload"] = await request.json()
        return web.Response(status=202)

    intake = web.Application()
    intake.router.add_post("/api/v2/spans", receive)
    server = await aiohttp_server(intake)
    monkeypatch.setitem(TRACE_INTAKE_URLS, "test.example", str(server.make_url("/api/v2/spans")))

    result = await forward_traces_to_v2_intake(
        [[{"trace_id": 1, "span_id": 2, "name": "span"}]],
        {"Datadog-Meta-Lang": "python", "X-Datadog-Test-Session-Token": "do-not-forward"},
        "test.example",
        "api-key",
        {"forwarded_by": "test-agent"},
    )

    assert result is True
    assert captured["headers"]["dd-api-key"] == "api-key"
    assert captured["headers"]["Datadog-Meta-Lang"] == "python"
    assert "X-Datadog-Test-Session-Token" not in captured["headers"]
    assert captured["payload"]["traces"][0]["spans"][0]["meta"]["_dd.compute_stats"] == "1"
    assert captured["payload"]["traces"][0]["spans"][0]["meta"]["forwarded_by"] == "test-agent"


async def test_forward_traces_to_v2_intake_requires_api_key(caplog):
    result = await forward_traces_to_v2_intake([], {}, "datadoghq.com", "")

    assert result is False
    assert "No DD_API_KEY" in caplog.text
