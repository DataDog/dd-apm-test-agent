"""OTLP Logs handling for the test agent."""

import json
import logging
from typing import Any
from typing import Dict

from aiohttp import ClientSession
from google.protobuf.json_format import MessageToDict
from grpc import aio as grpc_aio
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceResponse
from opentelemetry.proto.collector.logs.v1.logs_service_pb2_grpc import LogsServiceServicer


LOGS_ENDPOINT = "/v1/logs"


LOGS_ENDPOINT = "/v1/logs"


log = logging.getLogger(__name__)


def decode_logs_request(request_body: bytes, content_type: str) -> Dict[str, Any]:
    """Decode the protobuf request body into an ExportLogsServiceRequest object."""
    if content_type == "application/json":
        parsed_json = json.loads(request_body)
        if not isinstance(parsed_json, dict):
            raise Exception("JSON payload must be an object")
        return parsed_json
    elif content_type == "application/x-protobuf":
        export_request = ExportLogsServiceRequest()
        export_request.ParseFromString(request_body)
        return protobuf_to_dict(export_request)
    else:
        raise ValueError(f"Content-Type must be application/x-protobuf or application/json, got {content_type}")


def protobuf_to_dict(pb_obj: Any) -> Dict[str, Any]:
    """Convert a protobuf object to a dictionary."""
    return MessageToDict(pb_obj, preserving_proto_field_name=True)


class OTLPLogsGRPCServicer(LogsServiceServicer):
    """GRPC servicer that forwards OTLP logs to HTTP server."""

    def __init__(self, http_port: int):
        self.http_url = f"http://127.0.0.1:{http_port}"

    async def Export(
        self, request: ExportLogsServiceRequest, context: grpc_aio.ServicerContext
    ) -> ExportLogsServiceResponse:
        """Export logs by forwarding to HTTP server."""
        try:
            protobuf_data = request.SerializeToString()
            headers = {"Content-Type": "application/x-protobuf"}
            metadata = dict(context.invocation_metadata())
            if "session-token" in metadata:
                headers["Session-Token"] = metadata["session-token"]
            # Forward to OTLP HTTP server
            async with ClientSession(self.http_url) as session:
                async with session.post(LOGS_ENDPOINT, headers=headers, data=protobuf_data) as resp:
                    context.set_trailing_metadata([("http-status", str(resp.status))])
                    response = ExportLogsServiceResponse()
                    if resp.status >= 400:
                        response.partial_success.rejected_log_records = len(request.resource_logs)
                        response.partial_success.error_message = f"HTTP {resp.status}: {await resp.text()}"
                    return response
        except Exception as e:
            context.set_trailing_metadata([("http-status", "500"), ("error", str(e))])
            response = ExportLogsServiceResponse()
            response.partial_success.rejected_log_records = len(request.resource_logs)
            response.partial_success.error_message = f"Forward failed: {str(e)}"
            return response
