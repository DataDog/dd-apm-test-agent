import json
from typing import Any
from typing import Dict
from typing import cast


TelemetryEvent = Dict[str, Any]


def v2_decode(data: bytes) -> TelemetryEvent:
    """Decode v2 apm telemetry request data as a dict"""
    # TODO: Handle decoding into a telemetry payload object
    return cast(TelemetryEvent, json.loads(data))
