import base64
from urllib.parse import urlparse

import aiohttp
from aiohttp import web
import grpc
import grpc.aio as grpc_aio
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2_grpc import LogsServiceStub
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from opentelemetry.proto.common.v1.common_pb2 import KeyValue
from opentelemetry.proto.logs.v1.logs_pb2 import LogRecord
from opentelemetry.proto.logs.v1.logs_pb2 import ResourceLogs
from opentelemetry.proto.logs.v1.logs_pb2 import ScopeLogs
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
import pytest

from ddapm_test_agent.agent import make_otlp_http_app
from ddapm_test_agent.agent import make_otlp_grpc_server_async
from ddapm_test_agent.client import TestOTLPClient


# Constants
PROTOBUF_HEADERS = {"Content-Type": "application/x-protobuf"}
JSON_HEADERS = {"Content-Type": "application/json"}
OTLP_HTTP_PORT = 4318
OTLP_GRPC_PORT = 4317  # Future: GRPC support


def _find_service_name_in_resource(resource_logs, expected_service_name):
    """Check if service.name matches expected value in resource attributes."""
    if not resource_logs or not resource_logs[0].get("resource"):
        return False

    resource = resource_logs[0]["resource"]
    for attr in resource.get("attributes", []):
        if attr.get("key") == "service.name" and attr.get("value", {}).get("string_value") == expected_service_name:
            return True
    return False


@pytest.fixture
def service_name():
    """Service name."""
    return "ddservice"


@pytest.fixture
def environment():
    """Environment name."""
    return "ddenv"


@pytest.fixture
def version():
    """Service version."""
    return "ddv1"


@pytest.fixture
def host_name():
    """Host name."""
    return "ddhost"


@pytest.fixture
def log_message():
    """Log message content."""
    return "test_otel_logs_exporter_auto_configured_http"


@pytest.fixture
def trace_id():
    """Trace ID."""
    return b""


@pytest.fixture
def span_id():
    """Span ID."""
    return b""


@pytest.fixture
def otlp_logs_protobuf(service_name, environment, version, host_name, log_message, trace_id, span_id):
    """Serialize OTLP logs protobuf payload."""
    # Create resource attributes
    resource = Resource()
    resource.attributes.extend(
        [
            KeyValue(key="service.name", value=AnyValue(string_value=service_name)),
            KeyValue(key="deployment.environment", value=AnyValue(string_value=environment)),
            KeyValue(key="service.version", value=AnyValue(string_value=version)),
            KeyValue(key="host.name", value=AnyValue(string_value=host_name)),
        ]
    )

    # Create log record
    log_record = LogRecord()
    log_record.body.string_value = log_message
    log_record.trace_id = trace_id
    log_record.span_id = span_id

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

    return export_request

@pytest.fixture
def otlp_logs_string(otlp_logs_protobuf):
    """Serialize OTLP logs protobuf payload."""
    return otlp_logs_protobuf.SerializeToString()


@pytest.fixture
def otlp_logs_json(service_name, environment, version, host_name, log_message, trace_id, span_id):
    """JSON representation of OTLP logs payload."""
    return {
        "resource_logs": [
            {
                "resource": {
                    "attributes": [
                        {"key": "service.name", "value": {"string_value": service_name}},
                        {"key": "deployment.environment", "value": {"string_value": environment}},
                        {"key": "service.version", "value": {"string_value": version}},
                        {"key": "host.name", "value": {"string_value": host_name}},
                    ]
                },
                "scope_logs": [
                    {
                        "log_records": [
                            {
                                "body": {"string_value": log_message},
                                "trace_id": trace_id.hex() if trace_id else "",
                                "span_id": span_id.hex() if span_id else "",
                            }
                        ]
                    }
                ],
            }
        ]
    }


@pytest.fixture
async def otlp_http_agent(agent_app, aiohttp_client):
    """Test client for OTLP HTTP app."""
    # Get the shared agent instance from the main app
    agent = agent_app.app["agent"]
    otlp_http_app = make_otlp_http_app(agent)

    # Create a client for the OTLP HTTP app
    client = await aiohttp_client(otlp_http_app)
    yield client


@pytest.fixture
def otlp_http_url(testagent_url):
    """URL for OTLP HTTP logs endpoint."""
    parsed_url = urlparse(testagent_url)
    return f"{parsed_url.scheme}://{parsed_url.hostname}:{OTLP_HTTP_PORT}"


@pytest.fixture
def otlp_client(otlp_http_url):
    """Test Agent client for retrieving logs from the OTLP HTTP endpoint."""
    parsed_url = urlparse(otlp_http_url)
    client = TestOTLPClient(parsed_url.hostname, parsed_url.port, parsed_url.scheme)
    client.clear()
    client.wait_to_start()
    yield client
    client.clear()

@pytest.fixture
async def otlp_grpc_agent(agent_app):
    """GRPC server fixture for testing."""
    # Get the shared agent instance from the main app
    agent = agent_app.app["agent"]
    # Create GRPC server that forwards to the HTTP server
    server = await make_otlp_grpc_server_async(
            agent, OTLP_HTTP_PORT, OTLP_GRPC_PORT
        )

    yield server

    await server.stop(grace=5.0)


@pytest.fixture
async def otlp_grpc_client():
    """GRPC client for testing."""
    # Create GRPC channel and stub
    channel = grpc_aio.insecure_channel(f"localhost:{OTLP_GRPC_PORT}")
    stub = LogsServiceStub(channel)

    yield stub

    await channel.close()



async def test_logs_endpoint_basic_http(otlp_http_agent, otlp_logs_string):
    """POST /v1/logs accepts OTLP logs over HTTP and returns 200."""
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200


@pytest.mark.parametrize(
    "service_name,environment,version,host_name,log_message,trace_id,span_id",
    [
        (
            "web-service",
            "production",
            "1.0.0",
            "web-01",
            "User login successful",
            b"\xdd\xda\xa1\xa9\xa5y\xc1\xbd",
            b"h\x9b[\xe5\x00\x00\x00\x00\x80\x1b\\]\x1c#\xe6\xfb",
        ),
        (
            "api-service",
            "staging",
            "2.1.3",
            "api-02",
            "Database connection established",
            b"h\xb8\xcf\xb9\xa5;\x0f\x87",
            b"h\x9b[\xe5\x00\x00\x00\x00\x83\x0f\xb8M\xc8\xac\xd6Z",
        ),
        (
            "payment-service",
            "development",
            "0.9.5",
            "payment-03",
            "Payment processed successfully",
            b"\xee\x1fl\xf8d\x9a\xc2+",
            b"h\x9b[\xe5\x00\x00\x00\x00v{\xd8\xfd5+K(",
        ),
        ("auth-service", "test", "3.2.1", "auth-04", "Token validation failed", b"", b""),  # Empty trace/span IDs
        (
            "notification-service",
            "production",
            "1.5.7",
            "notify-05",
            "Email sent to user@example.com",
            b"\xb0\x10)\xbaI\xbc\x9d\xf1",
            b"h\x9b[\xe5\x00\x00\x00\x00k_$\x95`\n\xbf\xc5",
        ),
    ],
)
async def test_session_logs_endpoint_http(
    otlp_http_agent, otlp_logs_string, service_name, environment, version, host_name, log_message, span_id, trace_id
):
    """GET /test/session/logs returns stored logs with correct attributes via HTTP."""
    # Send logs
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200

    # Get logs from session
    resp = await otlp_http_agent.get("/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1
    assert "resource_logs" in logs[0]

    # Verify basic structure and content
    resource_logs = logs[0]["resource_logs"]
    assert len(resource_logs) == 1

    # Check that service.name is set in resource attributes
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"

    # Check that log message body is not null
    assert len(resource_logs) == 1
    resource = resource_logs[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
        {"key": "host.name", "value": {"string_value": host_name}},
    ]
    scope_logs = resource_logs[0].get("scope_logs", [])
    assert len(scope_logs) == 1
    log_records = scope_logs[0]["log_records"]
    assert len(log_records) == 1
    assert log_records[0]["body"].get("string_value") == log_message
    # trace_id and span_id are stored as hex strings in JSON
    expected_trace_id = base64.b64encode(trace_id).decode("ascii") if trace_id else None
    expected_span_id = base64.b64encode(span_id).decode("ascii") if span_id else None
    assert log_records[0].get("trace_id") == expected_trace_id
    assert log_records[0].get("span_id") == expected_span_id


async def test_otlp_client_logs(testagent, otlp_client, otlp_http_url, otlp_logs_string, service_name):
    """TestAgentClient.logs() retrieves stored logs correctly via HTTP."""
    # Send logs via aiohttp session to the OTLP HTTP port
    async with aiohttp.ClientSession() as session:
        resp = await session.post(f"{otlp_http_url}/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
        assert resp.status == 200

    # Wait for logs to be received
    otlp_client.wait_for_num_logs(1)

    # Get request from the OTLP HTTP port
    resp = otlp_client.requests()
    assert len(resp) == 1
    assert resp[0]["method"] == "POST"
    assert resp[0]["url"] == f"{otlp_http_url}/v1/logs"
    assert resp[0]["headers"]["Content-Type"] == PROTOBUF_HEADERS["Content-Type"]
    decoded_body = base64.b64decode(resp[0]["body"])
    assert decoded_body == otlp_logs_string, f"body: {resp[0]['body']} decoded: {decoded_body}, otlp_logs_string: {otlp_logs_string}"

    # Get logs via TestAgentClient from the OTLP HTTP port
    logs = otlp_client.logs()
    assert len(logs) == 1
    assert "resource_logs" in logs[0]

    otlp_client.clear()
    logs = otlp_client.logs()
    assert len(logs) == 0


async def test_logs_endpoint_integration_http(otlp_http_agent, otlp_logs_string, service_name, log_message):
    """End-to-end OTLP logs flow via HTTP: send logs, retrieve them, validate content."""
    # Clear any existing data
    resp = await otlp_http_agent.get("/test/session/clear")
    assert resp.status == 200

    # Send logs request
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200

    # Retrieve the logs
    resp = await otlp_http_agent.get("/test/session/logs")
    assert resp.status == 200
    captured_logs_list = await resp.json()

    # Verify we got at least one resource log
    assert len(captured_logs_list) > 0, "Expected at least one resource log"

    captured_logs = captured_logs_list[0]
    resource_logs = captured_logs["resource_logs"]
    assert len(resource_logs) > 0

    # Verify service.name is set in resource attributes
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"

    # Verify log message body is not null
    scope_logs = resource_logs[0].get("scope_logs", [])
    assert len(scope_logs) == 1
    log_records = scope_logs[0]["log_records"]
    assert len(log_records) == 1
    assert log_records[0]["body"].get("string_value") == log_message


async def test_multiple_logs_sessions_http(otlp_http_agent, otlp_logs_string):
    """Logs are isolated between sessions via HTTP."""
    # Send first log
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200

    # Start a new session
    resp = await otlp_http_agent.get("/test/session/start")
    assert resp.status == 200

    # Send second log in new session
    resp = await otlp_http_agent.post("/v1/logs", headers=PROTOBUF_HEADERS, data=otlp_logs_string)
    assert resp.status == 200

    # Get logs from current session (should only have one log)
    resp = await otlp_http_agent.get("/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1  # Only the log from the current session


async def test_logs_endpoint_json_http(otlp_http_agent, otlp_logs_json, service_name):
    """POST /v1/logs accepts JSON logs and returns 200."""
    import json

    resp = await otlp_http_agent.post("/v1/logs", headers=JSON_HEADERS, data=json.dumps(otlp_logs_json))
    assert resp.status == 200

    # Verify logs were stored
    resp = await otlp_http_agent.get("/test/session/logs")
    assert resp.status == 200
    logs = await resp.json()
    assert len(logs) == 1

    # Verify service.name is set in resource attributes
    resource_logs = logs[0]["resource_logs"]
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"


async def test_logs_endpoint_invalid_content_type(otlp_http_agent, otlp_logs_string):
    """POST /v1/logs rejects invalid content types."""
    # Test with XML content type (unsupported)
    resp = await otlp_http_agent.post("/v1/logs", headers={"Content-Type": "application/xml"}, data=otlp_logs_string)
    assert resp.status == 400

    # Test with plain text content type (unsupported)
    resp = await otlp_http_agent.post("/v1/logs", headers={"Content-Type": "text/plain"}, data=b"some plain text")
    assert resp.status == 400

    # Test with no content type header
    resp = await otlp_http_agent.post("/v1/logs", data=otlp_logs_string)
    assert resp.status == 400


async def test_logs_endpoint_invalid_json(otlp_http_agent):
    """POST /v1/logs rejects malformed JSON."""
    # Test malformed JSON syntax
    resp = await otlp_http_agent.post("/v1/logs", headers=JSON_HEADERS, data=b'{"invalid": json}')
    assert resp.status == 400

    # Test JSON array (should be object)
    resp = await otlp_http_agent.post("/v1/logs", headers=JSON_HEADERS, data=b'["not", "an", "object"]')
    assert resp.status == 400

    # Test JSON primitive (should be object)
    resp = await otlp_http_agent.post("/v1/logs", headers=JSON_HEADERS, data=b'"just a string"')
    assert resp.status == 400


async def test_logs_endpoint_basic_grpc(otlp_grpc_agent, otlp_grpc_client, otlp_logs_protobuf, loop):
    """Export logs via GRPC and verify they're forwarded to HTTP server."""
    # Call the GRPC Export method
    response = await otlp_grpc_client.Export(otlp_logs_protobuf)
    # Should return successful response
    assert response is not None


async def test_session_logs_endpoint_grpc_forwarding(testagent, otlp_grpc_client, otlp_client, otlp_logs_protobuf, service_name, log_message, loop):
    """Verify GRPC logs are forwarded to HTTP and retrievable via session endpoint."""
    # Send via GRPC
    response = await otlp_grpc_client.Export(otlp_logs_protobuf)
    assert response is not None

    # Verify logs are retrievable via HTTP session endpoint
    logs = otlp_client.logs()

    # Verify service.name is set in resource attributes
    resource_logs = logs[0]["resource_logs"]
    assert _find_service_name_in_resource(
        resource_logs, service_name
    ), f"service.name should be set to '{service_name}' in resource attributes"

    # Verify log message body is not null
    scope_logs = resource_logs[0].get("scope_logs", [])
    assert len(scope_logs) == 1
    log_records = scope_logs[0]["log_records"]
    assert len(log_records) == 1
    assert log_records[0]["body"].get("string_value") == log_message


async def test_grpc_maps_http_400_to_invalid_argument(aiohttp_server, agent_app, available_port):
    """GRPC forwarding maps HTTP 400 to GRPC INVALID_ARGUMENT."""
    # Minimal HTTP app that always returns 400 for /v1/logs
    async def bad_request_handler(_):
        raise web.HTTPBadRequest(text="invalid")

    http_app = web.Application()
    http_app.router.add_post("/v1/logs", bad_request_handler)
    http_server = await aiohttp_server(http_app)
    http_port = http_server.port

    # Start GRPC server forwarding to the above HTTP port on a free GRPC port
    grpc_port = int(available_port)
    agent = agent_app.app["agent"]
    grpc_server = await make_otlp_grpc_server_async(agent, http_port=http_port, grpc_port=grpc_port)

    try:
        channel = grpc_aio.insecure_channel(f"localhost:{grpc_port}")
        stub = LogsServiceStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as excinfo:
            await stub.Export(ExportLogsServiceRequest())
        assert excinfo.value.code() == grpc.StatusCode.INVALID_ARGUMENT
    finally:
        await channel.close()
        await grpc_server.stop(grace=0)


async def test_grpc_maps_http_500_to_internal(aiohttp_server, agent_app, available_port):
    """GRPC forwarding maps HTTP 500 to GRPC INTERNAL."""
    # Minimal HTTP app that returns 500 for /v1/logs
    async def internal_error_handler(_):
        raise web.HTTPInternalServerError(text="boom")

    http_app = web.Application()
    http_app.router.add_post("/v1/logs", internal_error_handler)
    http_server = await aiohttp_server(http_app)
    http_port = http_server.port

    # Start GRPC server forwarding to the above HTTP port on a free GRPC port
    grpc_port = int(available_port)
    agent = agent_app.app["agent"]
    grpc_server = await make_otlp_grpc_server_async(agent, http_port=http_port, grpc_port=grpc_port)

    try:
        channel = grpc_aio.insecure_channel(f"localhost:{grpc_port}")
        stub = LogsServiceStub(channel)
        with pytest.raises(grpc.aio.AioRpcError) as excinfo:
            await stub.Export(ExportLogsServiceRequest())
        assert excinfo.value.code() == grpc.StatusCode.INTERNAL
    finally:
        await channel.close()
        await grpc_server.stop(grace=0)
