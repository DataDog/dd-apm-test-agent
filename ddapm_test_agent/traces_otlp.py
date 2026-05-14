"""OTLP Traces handling for the test agent."""

import json
import logging
from typing import Any
from typing import Dict

from aiohttp import ClientSession
from google.protobuf.json_format import MessageToDict
from grpc import aio as grpc_aio
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceRequest
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import ExportTraceServiceResponse
from opentelemetry.proto.collector.trace.v1.trace_service_pb2_grpc import TraceServiceServicer


TRACES_ENDPOINT = "/v1/traces"


log = logging.getLogger(__name__)


def decode_traces_request(request_body: bytes, content_type: str) -> Dict[str, Any]:
    if content_type == "application/json":
        parsed_json = json.loads(request_body)
        if not isinstance(parsed_json, dict):
            raise Exception("JSON payload must be an object")
        return parsed_json
    elif content_type == "application/x-protobuf":
        export_request = ExportTraceServiceRequest()
        export_request.ParseFromString(request_body)
        return protobuf_to_dict(export_request)
    else:
        raise ValueError(f"Content-Type must be application/x-protobuf or application/json, got {content_type}")


def protobuf_to_dict(pb_obj: Any) -> Dict[str, Any]:
    return MessageToDict(pb_obj, preserving_proto_field_name=True)


class OTLPTracesGRPCServicer(TraceServiceServicer):

    def __init__(self, http_port: int):
        self.http_url = f"http://127.0.0.1:{http_port}"

    def _count_spans(self, request: ExportTraceServiceRequest) -> int:
        return sum(
            len(scope_span.spans)
            for resource_span in request.resource_spans
            for scope_span in resource_span.scope_spans
        )

    async def Export(
        self, request: ExportTraceServiceRequest, context: grpc_aio.ServicerContext
    ) -> ExportTraceServiceResponse:
        try:
            protobuf_data = request.SerializeToString()
            headers = {"Content-Type": "application/x-protobuf"}
            metadata = dict(context.invocation_metadata())
            if "session-token" in metadata:
                headers["Session-Token"] = metadata["session-token"]
            async with ClientSession(self.http_url) as session:
                async with session.post(TRACES_ENDPOINT, headers=headers, data=protobuf_data) as resp:
                    context.set_trailing_metadata([("http-status", str(resp.status))])
                    response = ExportTraceServiceResponse()
                    if resp.status >= 400:
                        response.partial_success.rejected_spans = self._count_spans(request)
                        response.partial_success.error_message = f"HTTP {resp.status}: {await resp.text()}"
                    return response
        except Exception as e:
            context.set_trailing_metadata([("http-status", "500"), ("error", str(e))])
            response = ExportTraceServiceResponse()
            response.partial_success.rejected_spans = self._count_spans(request)
            response.partial_success.error_message = f"Forward failed: {str(e)}"
            return response
