import json

from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from opentelemetry.proto.common.v1.common_pb2 import KeyValue
from opentelemetry.proto.logs.v1.logs_pb2 import LogRecord
from opentelemetry.proto.logs.v1.logs_pb2 import ResourceLogs
from opentelemetry.proto.logs.v1.logs_pb2 import ScopeLogs
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
import pytest

from ddapm_test_agent.client import TestAgentClient
from ddapm_test_agent.logs import find_log_correlation_attributes


def create_otlp_logs_protobuf():
    """Create a real OTLP logs protobuf payload for testing."""
    # Create resource attributes
    resource = Resource()
    resource.attributes.extend(
        [
            KeyValue(key="service.name", value=AnyValue(string_value="ddservice")),
            KeyValue(key="deployment.environment", value=AnyValue(string_value="ddenv")),
            KeyValue(key="service.version", value=AnyValue(string_value="ddv1")),
            KeyValue(key="host.name", value=AnyValue(string_value="ddhost")),
        ]
    )

    # Create log record
    log_record = LogRecord()
    log_record.body.string_value = "test_otel_logs_exporter_auto_configured_http"
    log_record.trace_id = b""  # Empty trace ID
    log_record.span_id = b""  # Empty span ID

    # Create scope logs
    scope_logs = ScopeLogs()
    scope_logs.log_records.append(log_record)

    # Create resource logs
    resource_logs = ResourceLogs()
    resource_logs.resource.CopyFrom(resource)
    resource_logs.scope_logs.append(scope_logs)

    # Create export request
    export_request = ExportLogsServiceRequest()
    export_request.resource_logs.append(resource_logs)

    return export_request.SerializeToString()


@pytest.fixture
async def test_agent_client(testagent, testagent_url):
    """Create a TestAgentClient from the testagent fixture."""
    return TestAgentClient(testagent_url)


@pytest.fixture
async def otlp_agent(agent_app, aiohttp_client, loop):
    """Create an OTLP client from the shared agent in agent_app."""
    from ddapm_test_agent.agent import make_otlp_app

    # Get the shared agent instance from the main app
    agent = agent_app.app["agent"]
    otlp_app = make_otlp_app(agent)

    # Create a client for the OTLP app
    client = await aiohttp_client(otlp_app)
    yield client


async def test_logs_endpoint_basic(otlp_agent):
    """Test that the /v1/logs endpoint accepts requests and returns 200."""
    # Create a real OTLP logs protobuf payload
    logs_data = create_otlp_logs_protobuf()

    headers = {
        "Content-Type": "application/x-protobuf",
    }

    resp = await otlp_agent.post("/v1/logs", headers=headers, data=logs_data)
    assert resp.status == 200


async def test_session_logs_endpoint(otlp_agent):
    """Test that the /test/session/logs endpoint returns logs for a session."""
    # Create a real OTLP logs protobuf payload
    logs_data = create_otlp_logs_protobuf()

    headers = {
        "Content-Type": "application/x-protobuf",
    }

    # Send logs
    resp = await otlp_agent.post("/v1/logs", headers=headers, data=logs_data)
    assert resp.status == 200

    # Get logs from session
    resp = await otlp_agent.get("/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1
    assert "resource_logs" in logs[0]

    # Verify the structure of the decoded logs
    resource_logs = logs[0]["resource_logs"]
    assert len(resource_logs) == 1

    # Check resource attributes
    resource = resource_logs[0]["resource"]
    assert "attributes" in resource

    # Check scope logs and log records
    scope_logs = resource_logs[0]["scope_logs"]
    assert len(scope_logs) == 1
    log_records = scope_logs[0]["log_records"]
    assert len(log_records) == 1

    # Check the log message
    log_body = log_records[0]["body"]["string_value"]
    assert log_body == "test_otel_logs_exporter_auto_configured_http"


async def test_client_logs_method(testagent, testagent_url):
    """Test the TestAgentClient logs() method."""
    from urllib.parse import urlparse

    import aiohttp

    # Create a TestAgentClient that points to the OTLP port for logs
    parsed_url = urlparse(testagent_url)
    otlp_url = f"{parsed_url.scheme}://{parsed_url.hostname}:4318"
    otlp_client = TestAgentClient(otlp_url)

    # Create a real OTLP logs protobuf payload
    logs_data = create_otlp_logs_protobuf()

    headers = {
        "Content-Type": "application/x-protobuf",
    }

    # Send logs via aiohttp session to the OTLP port
    async with aiohttp.ClientSession() as session:
        resp = await session.post(f"{otlp_url}/v1/logs", headers=headers, data=logs_data)
        assert resp.status == 200

    # Get logs via TestAgentClient from the OTLP port
    logs = otlp_client.logs()
    assert len(logs) == 1
    assert "resource_logs" in logs[0]


def test_find_log_correlation_attributes():
    """Test the log correlation attributes extraction function."""
    captured_logs = {
        "resource_logs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"string_value": "ddservice"}},
                        {"key": "deployment.environment", "value": {"string_value": "ddenv"}},
                        {"key": "service.version", "value": {"string_value": "ddv1"}},
                        {"key": "host.name", "value": {"string_value": "ddhost"}},
                    ]
                },
                "scope_logs": [
                    {
                        "log_records": [
                            {
                                "body": {"string_value": "test_otel_logs_exporter_auto_configured_http"},
                                "trace_id": "",
                                "span_id": "",
                            }
                        ]
                    }
                ],
            }
        ]
    }

    lc_attributes = find_log_correlation_attributes(captured_logs, "test_otel_logs_exporter_auto_configured_http")

    assert len(lc_attributes) == 6
    assert lc_attributes["service"] == "ddservice"
    assert lc_attributes["env"] == "ddenv"
    assert lc_attributes["version"] == "ddv1"
    assert lc_attributes["host_name"] == "ddhost"
    assert lc_attributes["trace_id"] == ""
    assert lc_attributes["span_id"] == ""


async def test_logs_endpoint_integration_like_user_example(otlp_agent):
    """Integration test that matches the pattern from the user query - realistic OTLP scenario."""
    # Clear any existing data
    resp = await otlp_agent.get("/test/session/clear")
    assert resp.status == 200

    # Simulate the user's test case scenario with real protobuf data
    logs_data = create_otlp_logs_protobuf()

    # Send logs request (simulating what OpenTelemetry exporter would do)
    headers = {
        "Content-Type": "application/x-protobuf",
    }

    resp = await otlp_agent.post("/v1/logs", headers=headers, data=logs_data)
    assert resp.status == 200

    # Retrieve the logs (as the test case would do)
    resp = await otlp_agent.get("/test/session/logs")
    assert resp.status == 200
    captured_logs_list = await resp.json()

    # Verify we got at least one resource log
    assert len(captured_logs_list) > 0, "Expected at least one resource log in the OpenTelemetry logs request"

    captured_logs = captured_logs_list[0]
    assert len(captured_logs["resource_logs"]) > 0

    # Test the correlation attributes extraction (as per user's test case)
    lc_attributes = find_log_correlation_attributes(captured_logs, "test_otel_logs_exporter_auto_configured_http")

    # Assert all the conditions from the user's test case
    assert len(lc_attributes) == 6, f"Expected 6 log correlation attributes but found: {lc_attributes}"
    assert (
        lc_attributes["service"] == "ddservice"
    ), f"Expected service.name to be 'ddservice' but found: {lc_attributes['service']}"
    assert (
        lc_attributes["env"] == "ddenv"
    ), f"Expected deployment.environment to be 'ddenv' but found: {lc_attributes['env']}"
    assert (
        lc_attributes["version"] == "ddv1"
    ), f"Expected service.version to be 'ddv1' but found: {lc_attributes['version']}"
    assert (
        lc_attributes["host_name"] == "ddhost"
    ), f"Expected host.name to be 'ddhost' but found: {lc_attributes['host_name']}"
    assert lc_attributes["trace_id"] in (
        "00000000000000000000000000000000",
        "",
    ), f"Expected trace_id to be '00000000000000000000000000000000' but found: {lc_attributes['trace_id']}"
    assert lc_attributes["span_id"] in (
        "0000000000000000",
        "",
    ), f"Expected span_id to be '0000000000000000' but found: {lc_attributes['span_id']}"


async def test_multiple_logs_sessions(otlp_agent):
    """Test that logs are properly isolated between sessions."""
    # Send first log
    logs_data_1 = create_otlp_logs_protobuf()
    resp = await otlp_agent.post("/v1/logs", headers={"Content-Type": "application/x-protobuf"}, data=logs_data_1)
    assert resp.status == 200

    # Start a new session
    resp = await otlp_agent.get("/test/session/start")
    assert resp.status == 200

    # Send second log in new session
    logs_data_2 = create_otlp_logs_protobuf()
    resp = await otlp_agent.post("/v1/logs", headers={"Content-Type": "application/x-protobuf"}, data=logs_data_2)
    assert resp.status == 200

    # Get logs from current session (should only have one log)
    resp = await otlp_agent.get("/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1  # Only the log from the current session
