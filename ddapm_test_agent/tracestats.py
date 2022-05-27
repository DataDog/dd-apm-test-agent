from typing import List
from typing import Optional
from typing import TypedDict

from ddsketch import DDSketch
from ddsketch.pb.ddsketch_pb2 import DDSketch as DDSketchProto
from google.protobuf.json_format import MessageToDict
import msgpack


# Note that class attributes are golang style to match the payload.


class StatsAggr(TypedDict):
    Name: str
    Resource: str
    Type: Optional[str]  # noqa
    HTTPStatusCode: int
    Synthetics: bool
    Hits: int
    TopLevelHits: int
    Duration: int
    Errors: int
    OkSummary: DDSketch
    ErrorSummary: DDSketch


class StatsBucket(TypedDict):
    Start: int
    Duration: int
    Stats: List[StatsAggr]


class v06StatsPayload(TypedDict):
    Hostname: Optional[str]
    Env: Optional[str]
    Version: Optional[str]
    Stats: List[StatsBucket]


def decode_v06(data: bytes) -> v06StatsPayload:
    payload = msgpack.unpackb(data)
    stats_buckets: List[StatsBucket] = []
    for raw_bucket in payload["Stats"]:
        stats: List[StatsAggr] = []
        for raw_stats in raw_bucket["Stats"]:
            ok_summary = DDSketchProto()
            ok_summary.ParseFromString(raw_stats["OkSummary"])
            err_summary = DDSketchProto()
            err_summary.ParseFromString(raw_stats["ErrorSummary"])
            stat = StatsAggr(
                Name=raw_stats["Name"],
                Resource=raw_stats["Resource"],
                Type=raw_stats.get("Type"),
                HTTPStatusCode=raw_stats.get("HTTPStatusCode"),
                Synthetics=raw_stats["Synthetics"],
                Hits=raw_stats["Hits"],
                TopLevelHits=raw_stats["TopLevelHits"],
                Duration=raw_stats["Duration"],
                Errors=raw_stats["Errors"],
                OkSummary=MessageToDict(ok_summary),
                ErrorSummary=MessageToDict(err_summary),
            )
            stats.append(stat)

        bucket = StatsBucket(
            Start=raw_bucket["Start"],
            Duration=raw_bucket["Duration"],
            Stats=stats,
        )
        stats_buckets.append(bucket)

    return v06StatsPayload(
        Hostname=payload.get("Hostname"),
        Env=payload.get("Env"),
        Version=payload.get("Version"),
        Stats=stats_buckets,
    )
