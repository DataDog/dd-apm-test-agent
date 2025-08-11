"""OTLP Logs handling for the test agent."""

import logging
from typing import Any
from typing import Dict

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest


log = logging.getLogger(__name__)


def decode_logs_request(request_body: bytes) -> Dict[str, Any]:
    """Decode the protobuf request body into an ExportLogsServiceRequest object."""
    try:
        export_request = ExportLogsServiceRequest()
        export_request.ParseFromString(request_body)
        return protobuf_to_dict(export_request)
    except Exception as e:
        log.error(f"Failed to decode OTLP logs request: {e}")
        raise ValueError(f"Invalid OTLP logs protobuf payload: {e}") from e


def protobuf_to_dict(pb_obj: Any) -> Dict[str, Any]:
    """Convert a protobuf object to a dictionary."""
    return MessageToDict(pb_obj, preserving_proto_field_name=True)
