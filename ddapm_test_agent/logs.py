"""OTLP Logs handling for the test agent."""

import logging
import json
from typing import Any
from typing import Dict

from google.protobuf.json_format import MessageToDict
from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest


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
