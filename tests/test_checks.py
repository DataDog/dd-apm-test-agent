# import time

# import pytest

# from .conftest import v04_trace
# from .trace_utils import span


# async def test_reference(
#     agent,
#     v04_reference_http_trace_payload_headers,
#     v04_reference_http_trace_payload_data,
# ):
#     resp = await agent.put(
#         "/v0.4/traces",
#         headers=v04_reference_http_trace_payload_headers,
#         data=v04_reference_http_trace_payload_data,
#     )
#     assert resp.status == 200, await resp.text()


async def test_reference_case_insensitive(
    agent,
    v04_reference_http_trace_payload_data,
):
    resp = await agent.put(
        "/v0.4/traces",
        headers={
            "content-type": "application/msgpack",
            "x-datadog-trace-count": "1",
            "datadog-meta-tracer-version": "v0.1",
        },
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()


@pytest.mark.parametrize("agent_disabled_checks", [[], ["trace_count_header"]])
async def test_trace_count_header(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
    agent_disabled_checks,
):
    del v04_reference_http_trace_payload_headers["X-Datadog-Trace-Count"]
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    if "trace_count_header" in agent_disabled_checks:
        assert resp.status == 200, await resp.text()
    else:
        assert resp.status == 400, await resp.text()
        assert "Check 'trace_count_header' failed" in await resp.text()


# async def test_trace_count_header_mismatch(
#     agent,
#     v04_reference_http_trace_payload_headers,
#     v04_reference_http_trace_payload_data,
# ):
#     v04_reference_http_trace_payload_headers["X-Datadog-Trace-Count"] += "1"
#     resp = await agent.put(
#         "/v0.4/traces",
#         headers=v04_reference_http_trace_payload_headers,
#         data=v04_reference_http_trace_payload_data,
#     )
#     assert resp.status == 400, await resp.text()
#     assert "Check 'trace_count_header' failed" in await resp.text()


# @pytest.mark.parametrize("agent_disabled_checks", [[], ["meta_tracer_version_header"]])
# async def test_meta_tracer_version_header(
#     agent,
#     v04_reference_http_trace_payload_headers,
#     v04_reference_http_trace_payload_data,
#     agent_disabled_checks,
# ):
#     del v04_reference_http_trace_payload_headers["Datadog-Meta-Tracer-Version"]
#     resp = await agent.put(
#         "/v0.4/traces",
#         headers=v04_reference_http_trace_payload_headers,
#         data=v04_reference_http_trace_payload_data,
#     )
#     if "meta_tracer_version_header" in agent_disabled_checks:
#         assert resp.status == 200, await resp.text()
#     else:
#         assert resp.status == 400, await resp.text()
#         assert "Check 'meta_tracer_version_header' failed" in await resp.text()


# async def test_trace_content_length(agent):
#     # Assume a trace will be at least 100 bytes each
#     s = span()
#     trace = [s for _ in range(int(5e7 / 100))]
#     resp = await v04_trace(agent, [trace], "msgpack")
#     assert resp.status == 400, await resp.text()
#     assert "Check 'trace_content_length' failed: content length" in await resp.text()


# # async def test_trace_stall(
# #     agent,
# #     v04_reference_http_trace_payload_headers,
# #     v04_reference_http_trace_payload_data,
# #     agent_disabled_checks,
# # ):
# #     v04_reference_http_trace_payload_headers["X-Datadog-Test-Stall-Seconds"] = "0.8"
# #     start = time.monotonic_ns()
# #     resp = await agent.put(
# #         "/v0.4/traces",
# #         headers=v04_reference_http_trace_payload_headers,
# #         data=v04_reference_http_trace_payload_data,
# #     )
# #     assert resp.status == 200, await resp.text()
# #     end = time.monotonic_ns()
# #     assert (end - start) / 1e9 >= 0.8
