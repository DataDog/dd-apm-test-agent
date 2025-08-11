"""OTLP Logs handling for the test agent."""

import logging
from typing import Any
from typing import Dict
from typing import List

from opentelemetry.proto.collector.logs.v1.logs_service_pb2 import ExportLogsServiceRequest


log = logging.getLogger(__name__)


def decode_logs_request(request_body: bytes) -> Dict[str, Any]:
    """
    Decode the protobuf request body into an ExportLogsServiceRequest object.
    """
    export_request = ExportLogsServiceRequest()
    export_request.ParseFromString(request_body)
    # Convert to dict for JSON serialization and easier handling
    return protobuf_to_dict(export_request)


def protobuf_to_dict(pb_obj: Any) -> Dict[str, Any]:
    """Convert a protobuf object to a dictionary."""
    from google.protobuf.json_format import MessageToDict

    return MessageToDict(pb_obj, preserving_proto_field_name=True)


def find_log_correlation_attributes(captured_logs: Dict[str, Any], expected_message: str) -> Dict[str, str]:
    """
    Find log correlation attributes from captured logs for a specific log message.

    This function searches through the captured logs to find a log record with the expected message
    and extracts correlation attributes like service, env, version, etc.
    """
    correlation_attrs = {}

    if "resource_logs" not in captured_logs:
        return correlation_attrs

    for resource_log in captured_logs["resource_logs"]:
        # Extract resource attributes
        resource_attrs = {}
        if "resource" in resource_log and "attributes" in resource_log["resource"]:
            for attr in resource_log["resource"]["attributes"]:
                key = attr.get("key", "")
                value_obj = attr.get("value", {})
                if "string_value" in value_obj:
                    resource_attrs[key] = value_obj["string_value"]

        # Check scope logs for the expected message
        if "scope_logs" not in resource_log:
            continue

        for scope_log in resource_log["scope_logs"]:
            if "log_records" not in scope_log:
                continue

            for log_record in scope_log["log_records"]:
                # Check if this is the log record we're looking for
                body = log_record.get("body", {})
                if "string_value" in body and expected_message in body["string_value"]:
                    # Found the log record, extract correlation attributes

                    # Map resource attributes to correlation attributes
                    if "service.name" in resource_attrs:
                        correlation_attrs["service"] = resource_attrs["service.name"]
                    if "deployment.environment" in resource_attrs:
                        correlation_attrs["env"] = resource_attrs["deployment.environment"]
                    if "service.version" in resource_attrs:
                        correlation_attrs["version"] = resource_attrs["service.version"]
                    if "host.name" in resource_attrs:
                        correlation_attrs["host_name"] = resource_attrs["host.name"]

                    # Extract trace and span IDs
                    trace_id = log_record.get("trace_id", "")
                    span_id = log_record.get("span_id", "")

                    # Convert bytes to hex string if needed
                    if isinstance(trace_id, bytes):
                        correlation_attrs["trace_id"] = trace_id.hex() if trace_id else ""
                    else:
                        correlation_attrs["trace_id"] = trace_id if trace_id else ""

                    if isinstance(span_id, bytes):
                        correlation_attrs["span_id"] = span_id.hex() if span_id else ""
                    else:
                        correlation_attrs["span_id"] = span_id if span_id else ""

                    return correlation_attrs

    return correlation_attrs
