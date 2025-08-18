"""OTLP Metrics handling for the test agent."""

import json
import logging
from typing import Any
from typing import Dict

from aiohttp import ClientSession
from google.protobuf.json_format import MessageToDict
from grpc import aio as grpc_aio
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceRequest
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2 import ExportMetricsServiceResponse
from opentelemetry.proto.collector.metrics.v1.metrics_service_pb2_grpc import MetricsServiceServicer


METRICS_ENDPOINT = "/v1/metrics"


log = logging.getLogger(__name__)


def decode_metrics_request(request_body: bytes, content_type: str) -> Dict[str, Any]:
    if content_type == "application/json":
        parsed_json = json.loads(request_body)
        if not isinstance(parsed_json, dict):
            raise Exception("JSON payload must be an object")
        return parsed_json
    elif content_type == "application/x-protobuf":
        export_request = ExportMetricsServiceRequest()
        export_request.ParseFromString(request_body)
        return protobuf_to_dict(export_request)
    else:
        raise ValueError(f"Content-Type must be application/x-protobuf or application/json, got {content_type}")


def protobuf_to_dict(pb_obj: Any) -> Dict[str, Any]:
    return MessageToDict(pb_obj, preserving_proto_field_name=True)


class OTLPMetricsGRPCServicer(MetricsServiceServicer):

    def __init__(self, http_port: int):
        self.http_url = f"http://127.0.0.1:{http_port}"

    def _count_data_points(self, request: ExportMetricsServiceRequest) -> int:
        return len(
            [
                dp
                for rm in request.resource_metrics
                for sm in rm.scope_metrics
                for m in sm.metrics
                for dp in (
                    m.gauge.data_points
                    if m.HasField("gauge")
                    else (
                        m.sum.data_points
                        if m.HasField("sum")
                        else (
                            m.histogram.data_points
                            if m.HasField("histogram")
                            else (
                                m.exponential_histogram.data_points
                                if m.HasField("exponential_histogram")
                                else m.summary.data_points if m.HasField("summary") else []
                            )
                        )
                    )
                )
            ]
        )

    async def Export(
        self, request: ExportMetricsServiceRequest, context: grpc_aio.ServicerContext
    ) -> ExportMetricsServiceResponse:
        try:
            protobuf_data = request.SerializeToString()
            headers = {"Content-Type": "application/x-protobuf"}
            metadata = dict(context.invocation_metadata())
            if "session-token" in metadata:
                headers["Session-Token"] = metadata["session-token"]
            async with ClientSession(self.http_url) as session:
                async with session.post(METRICS_ENDPOINT, headers=headers, data=protobuf_data) as resp:
                    context.set_trailing_metadata([("http-status", str(resp.status))])
                    response = ExportMetricsServiceResponse()
                    if resp.status >= 400:
                        response.partial_success.rejected_data_points = self._count_data_points(request)
                        response.partial_success.error_message = f"HTTP {resp.status}: {await resp.text()}"
                    return response
        except Exception as e:
            context.set_trailing_metadata([("http-status", "500"), ("error", str(e))])
            response = ExportMetricsServiceResponse()
            response.partial_success.rejected_data_points = self._count_data_points(request)
            response.partial_success.error_message = f"Forward failed: {str(e)}"
            return response
