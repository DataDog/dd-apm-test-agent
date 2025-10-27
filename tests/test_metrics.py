import base64
import json

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceResponse
from opentelemetry.proto.common.v1.common_pb2 import AnyValue
from opentelemetry.proto.common.v1.common_pb2 import KeyValue
from opentelemetry.proto.metrics.v1.metrics_pb2 import AggregationTemporality
from opentelemetry.proto.metrics.v1.metrics_pb2 import ExponentialHistogram
from opentelemetry.proto.metrics.v1.metrics_pb2 import ExponentialHistogramDataPoint
from opentelemetry.proto.metrics.v1.metrics_pb2 import Gauge
from opentelemetry.proto.metrics.v1.metrics_pb2 import Histogram
from opentelemetry.proto.metrics.v1.metrics_pb2 import HistogramDataPoint
from opentelemetry.proto.metrics.v1.metrics_pb2 import Metric
from opentelemetry.proto.metrics.v1.metrics_pb2 import NumberDataPoint
from opentelemetry.proto.metrics.v1.metrics_pb2 import ResourceMetrics
from opentelemetry.proto.metrics.v1.metrics_pb2 import ScopeMetrics
from opentelemetry.proto.metrics.v1.metrics_pb2 import Sum
from opentelemetry.proto.metrics.v1.metrics_pb2 import Summary
from opentelemetry.proto.metrics.v1.metrics_pb2 import SummaryDataPoint
from opentelemetry.proto.resource.v1.resource_pb2 import Resource
import pytest

from ddapm_test_agent.metrics import METRICS_ENDPOINT
from tests.conftest import JSON_HEADERS
from tests.conftest import PROTOBUF_HEADERS
from tests.conftest import _get_http_status_from_metadata


@pytest.fixture
def metric_name():
    return "test.counter"


@pytest.fixture
def metric_value():
    return 42.0


@pytest.fixture
def gauge_metric(metric_name, metric_value):
    data_point = NumberDataPoint()
    data_point.as_double = metric_value
    data_point.time_unix_nano = 1609459200000000000

    gauge = Gauge()
    gauge.data_points.append(data_point)

    metric = Metric()
    metric.name = f"{metric_name}.gauge"
    metric.description = f"Test {metric_name} gauge metric"
    metric.unit = "1"
    metric.gauge.CopyFrom(gauge)
    return metric


@pytest.fixture
def sum_metric(metric_name, metric_value):
    data_point = NumberDataPoint()
    data_point.as_double = metric_value + 10
    data_point.time_unix_nano = 1609459200000000000

    sum_metric = Sum()
    sum_metric.aggregation_temporality = AggregationTemporality.AGGREGATION_TEMPORALITY_CUMULATIVE
    sum_metric.is_monotonic = True
    sum_metric.data_points.append(data_point)

    metric = Metric()
    metric.name = f"{metric_name}.sum"
    metric.description = f"Test {metric_name} sum metric"
    metric.unit = "1"
    metric.sum.CopyFrom(sum_metric)
    return metric


@pytest.fixture
def histogram_metric(metric_name):
    data_point = HistogramDataPoint()
    data_point.count = 5
    data_point.sum = 15.0
    data_point.bucket_counts.extend([1, 2, 1, 1])
    data_point.explicit_bounds.extend([0.0, 5.0, 10.0, 25.0])
    data_point.time_unix_nano = 1609459200000000000

    histogram = Histogram()
    histogram.aggregation_temporality = AggregationTemporality.AGGREGATION_TEMPORALITY_CUMULATIVE
    histogram.data_points.append(data_point)

    metric = Metric()
    metric.name = f"{metric_name}.histogram"
    metric.description = f"Test {metric_name} histogram metric"
    metric.unit = "ms"
    metric.histogram.CopyFrom(histogram)
    return metric


@pytest.fixture
def exponential_histogram_metric(metric_name):
    data_point = ExponentialHistogramDataPoint()
    data_point.count = 3
    data_point.sum = 12.0
    data_point.scale = 1
    data_point.zero_count = 0
    data_point.positive.offset = 0
    data_point.positive.bucket_counts.extend([1, 1, 1])
    data_point.time_unix_nano = 1609459200000000000

    exp_histogram = ExponentialHistogram()
    exp_histogram.aggregation_temporality = AggregationTemporality.AGGREGATION_TEMPORALITY_CUMULATIVE
    exp_histogram.data_points.append(data_point)

    metric = Metric()
    metric.name = f"{metric_name}.exp_histogram"
    metric.description = f"Test {metric_name} exponential histogram metric"
    metric.unit = "bytes"
    metric.exponential_histogram.CopyFrom(exp_histogram)
    return metric


@pytest.fixture
def summary_metric(metric_name):
    data_point = SummaryDataPoint()
    data_point.count = 4
    data_point.sum = 20.0
    data_point.time_unix_nano = 1609459200000000000

    summary = Summary()
    summary.data_points.append(data_point)

    metric = Metric()
    metric.name = f"{metric_name}.summary"
    metric.description = f"Test {metric_name} summary metric"
    metric.unit = "s"
    metric.summary.CopyFrom(summary)
    return metric


@pytest.fixture
def otlp_metrics_protobuf(
    service_name,
    environment,
    version,
    gauge_metric,
    sum_metric,
    histogram_metric,
    exponential_histogram_metric,
    summary_metric,
):
    resource = Resource()
    resource.attributes.extend(
        [
            KeyValue(key="service.name", value=AnyValue(string_value=service_name)),
            KeyValue(key="deployment.environment.name", value=AnyValue(string_value=environment)),
            KeyValue(key="service.version", value=AnyValue(string_value=version)),
        ]
    )

    scope_metrics = ScopeMetrics()
    scope_metrics.metrics.extend(
        [
            gauge_metric,
            sum_metric,
            histogram_metric,
            exponential_histogram_metric,
            summary_metric,
        ]
    )

    resource_metrics = ResourceMetrics()
    resource_metrics.resource.CopyFrom(resource)
    resource_metrics.scope_metrics.append(scope_metrics)

    export_request = ExportMetricsServiceRequest()
    export_request.resource_metrics.append(resource_metrics)

    return export_request


@pytest.fixture
def otlp_metrics_string(otlp_metrics_protobuf):
    return otlp_metrics_protobuf.SerializeToString()


@pytest.fixture
def otlp_metrics_json(otlp_metrics_protobuf):
    return json.dumps(MessageToDict(otlp_metrics_protobuf, preserving_proto_field_name=True))


async def test_metrics_endpoint_basic_http(testagent, otlp_http_url, otlp_metrics_string, loop):
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200
    assert resp.content_type == "application/x-protobuf"
    body = await resp.read()
    assert body == ExportMetricsServiceResponse().SerializeToString()


@pytest.mark.parametrize(
    "service_name,environment,version,metric_name,metric_value",
    [
        (
            "web-service",
            "production",
            "1.0.0",
            "http.requests.total",
            123.0,
        ),
        (
            "api-service",
            "staging",
            "2.1.3",
            "db.connections.active",
            15.0,
        ),
        (
            "payment-service",
            "development",
            "0.9.5",
            "payments.processed",
            456.0,
        ),
    ],
)
async def test_session_metrics_endpoint_http(
    testagent,
    otlp_http_url,
    otlp_metrics_string,
    service_name,
    environment,
    version,
    metric_name,
    metric_value,
    loop,
):
    """Session endpoint returns metrics with all attributes preserved."""
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/metrics")
    assert resp.status == 200
    metrics = await resp.json()
    assert len(metrics) == 1
    assert "resource_metrics" in metrics[0]

    resource_metrics = metrics[0]["resource_metrics"]
    assert len(resource_metrics) == 1
    resource = resource_metrics[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]
    scope_metrics = resource_metrics[0].get("scope_metrics", [])
    assert len(scope_metrics) == 1
    metrics_list = scope_metrics[0]["metrics"]
    assert len(metrics_list) == 5  # Now we have 5 metric types

    # Find the gauge metric specifically
    gauge_metric = next(m for m in metrics_list if m["name"] == f"{metric_name}.gauge")
    assert gauge_metric["gauge"]["data_points"][0]["as_double"] == metric_value


async def test_otlp_client_metrics(testagent, otlp_test_client, otlp_http_url, otlp_metrics_string, loop):
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    otlp_test_client.wait_for_num_metrics(1)

    resp = otlp_test_client.requests()
    assert len(resp) == 1
    assert resp[0]["method"] == "POST"
    assert resp[0]["url"] == f"{otlp_http_url}{METRICS_ENDPOINT}"
    assert resp[0]["headers"]["Content-Type"] == PROTOBUF_HEADERS["Content-Type"]
    decoded_body = base64.b64decode(resp[0]["body"])
    assert (
        decoded_body == otlp_metrics_string
    ), f"body: {resp[0]['body']} decoded: {decoded_body}, otlp_metrics_string: {otlp_metrics_string}"

    metrics = otlp_test_client.metrics()
    assert len(metrics) == 1
    assert "resource_metrics" in metrics[0]

    otlp_test_client.clear()
    metrics = otlp_test_client.metrics()
    assert len(metrics) == 0


async def test_metrics_endpoint_integration_http(
    testagent, otlp_http_url, otlp_metrics_string, service_name, environment, version, metric_name, loop
):
    resp = await testagent.get(f"{otlp_http_url}/test/session/clear")
    assert resp.status == 200

    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/metrics")
    assert resp.status == 200
    captured_metrics_list = await resp.json()

    assert len(captured_metrics_list) > 0, "Expected at least one resource metric"

    captured_metrics = captured_metrics_list[0]
    resource_metrics = captured_metrics["resource_metrics"]
    assert len(resource_metrics) == 1

    # Check resource has expected attributes
    resource = resource_metrics[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]

    scope_metrics = resource_metrics[0].get("scope_metrics", [])
    assert len(scope_metrics) == 1
    metrics_list = scope_metrics[0]["metrics"]
    assert len(metrics_list) == 5  # Now we have 5 metric types

    # Verify all metric types are present
    metric_names = [m["name"] for m in metrics_list]
    expected_names = [
        f"{metric_name}.gauge",
        f"{metric_name}.sum",
        f"{metric_name}.histogram",
        f"{metric_name}.exp_histogram",
        f"{metric_name}.summary",
    ]
    assert all(name in metric_names for name in expected_names)


async def test_multiple_metrics_sessions_http(testagent, otlp_http_url, otlp_metrics_string, loop):
    """Metrics are isolated between sessions."""
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/start")
    assert resp.status == 200

    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=PROTOBUF_HEADERS, data=otlp_metrics_string
    )
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/metrics")
    assert resp.status == 200
    metrics = await resp.json()
    assert len(metrics) == 1  # Only the metric from the current session


async def test_metrics_endpoint_json_http(
    testagent, otlp_http_url, otlp_metrics_json, service_name, environment, version, loop
):
    resp = await testagent.post(f"{otlp_http_url}{METRICS_ENDPOINT}", headers=JSON_HEADERS, data=otlp_metrics_json)
    assert resp.status == 200

    resp = await testagent.get(f"{otlp_http_url}/test/session/metrics")
    assert resp.status == 200
    metrics = await resp.json()
    assert len(metrics) == 1

    resource_metrics = metrics[0]["resource_metrics"]
    assert len(resource_metrics) == 1

    # Check resource has expected attributes
    resource = resource_metrics[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]


async def test_metrics_endpoint_invalid_content_type(testagent, otlp_http_url, otlp_metrics_string, loop):
    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers={"Content-Type": "application/xml"}, data=otlp_metrics_string
    )
    assert resp.status == 400

    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers={"Content-Type": "text/plain"}, data=b"some plain text"
    )
    assert resp.status == 400

    resp = await testagent.post(f"{otlp_http_url}{METRICS_ENDPOINT}", data=otlp_metrics_string)
    assert resp.status == 400


async def test_metrics_endpoint_invalid_json(testagent, otlp_http_url, loop):
    resp = await testagent.post(f"{otlp_http_url}{METRICS_ENDPOINT}", headers=JSON_HEADERS, data=b'{"invalid": json}')
    assert resp.status == 400

    resp = await testagent.post(
        f"{otlp_http_url}{METRICS_ENDPOINT}", headers=JSON_HEADERS, data=b'["not", "an", "object"]'
    )
    assert resp.status == 400

    resp = await testagent.post(f"{otlp_http_url}{METRICS_ENDPOINT}", headers=JSON_HEADERS, data=b'"just a string"')
    assert resp.status == 400


async def test_metrics_endpoint_basic_grpc(testagent, otlp_metrics_grpc_client, otlp_metrics_protobuf, loop):
    call = otlp_metrics_grpc_client.Export(otlp_metrics_protobuf)
    response = await call

    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 200, f"Expected HTTP 200, got {http_status}"

    # For successful requests, partial_success should be empty
    assert response.partial_success.rejected_data_points == 0
    assert response.partial_success.error_message == ""


async def test_session_metrics_endpoint_grpc_forwarding(
    testagent,
    otlp_metrics_grpc_client,
    otlp_test_client,
    otlp_metrics_protobuf,
    service_name,
    environment,
    version,
    metric_name,
    loop,
):
    call = otlp_metrics_grpc_client.Export(otlp_metrics_protobuf)
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 200, f"Expected HTTP 200, got {http_status}"

    metrics = otlp_test_client.metrics()

    resource_metrics = metrics[0]["resource_metrics"]
    assert len(resource_metrics) == 1

    # Check resource has expected attributes
    resource = resource_metrics[0].get("resource", {})
    assert resource.get("attributes") == [
        {"key": "service.name", "value": {"string_value": service_name}},
        {"key": "deployment.environment.name", "value": {"string_value": environment}},
        {"key": "service.version", "value": {"string_value": version}},
    ]

    scope_metrics = resource_metrics[0].get("scope_metrics", [])
    assert len(scope_metrics) == 1
    metrics_list = scope_metrics[0]["metrics"]
    assert len(metrics_list) == 5  # Now we have 5 metric types

    # Verify all metric types are present
    metric_names = [m["name"] for m in metrics_list]
    expected_names = [
        f"{metric_name}.gauge",
        f"{metric_name}.sum",
        f"{metric_name}.histogram",
        f"{metric_name}.exp_histogram",
        f"{metric_name}.summary",
    ]
    assert all(name in metric_names for name in expected_names)


@pytest.mark.parametrize("grpc_client_with_failure_type", [("http_400", "metrics")], indirect=True)
async def test_grpc_maps_http_400_to_metadata(grpc_client_with_failure_type):
    """GRPC forwarding preserves HTTP 400 status in metadata and partial_success."""

    call = grpc_client_with_failure_type.Export(ExportMetricsServiceRequest())
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 400, f"Expected HTTP 400, got {http_status}"

    assert response.partial_success.rejected_data_points == 0  # Empty request
    assert "HTTP 400" in response.partial_success.error_message


@pytest.mark.parametrize("grpc_client_with_failure_type", [("http_500", "metrics")], indirect=True)
async def test_grpc_maps_http_500_to_metadata(grpc_client_with_failure_type):
    """GRPC forwarding preserves HTTP 500 status in metadata and partial_success."""

    call = grpc_client_with_failure_type.Export(ExportMetricsServiceRequest())
    response = await call
    assert response is not None

    http_status = await _get_http_status_from_metadata(call)
    assert http_status == 500, f"Expected HTTP 500, got {http_status}"

    assert response.partial_success.rejected_data_points == 0  # Empty request
    assert "HTTP 500" in response.partial_success.error_message


@pytest.mark.parametrize("grpc_client_with_failure_type", [("connection_failure", "metrics")], indirect=True)
async def test_grpc_server_resilience_after_failure(grpc_client_with_failure_type, otlp_metrics_protobuf):
    """GRPC server remains operational after processing failed requests."""

    call1 = grpc_client_with_failure_type.Export(otlp_metrics_protobuf)
    response1 = await call1
    assert response1 is not None

    assert response1.partial_success.rejected_data_points == 5  # 5 metrics with 1 data point each
    assert "Forward failed" in response1.partial_success.error_message

    http_status = await _get_http_status_from_metadata(call1)
    assert http_status == 500  # Connection failure mapped to 500

    call2 = grpc_client_with_failure_type.Export(otlp_metrics_protobuf)
    response2 = await call2
    assert response2 is not None

    assert response2.partial_success.rejected_data_points == 5  # 5 metrics with 1 data point each
    assert "Forward failed" in response2.partial_success.error_message

    call3 = grpc_client_with_failure_type.Export(ExportMetricsServiceRequest())
    response3 = await call3
    assert response3 is not None
