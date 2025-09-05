import base64
from typing import Dict

from aiohttp import BodyPartReader
from aiohttp import MultipartReader
from aiohttp import StreamReader
from aiohttp.web import Request


TracerFlareEvent = Dict[str, str]


async def v1_decode(request: Request, data: bytes) -> TracerFlareEvent:
    """Decode v1 tracer flare form as a dict"""
    tracer_flare: TracerFlareEvent = {}

    try:
        stream = StreamReader(request.protocol, len(data))
        stream.feed_data(data)
        stream.feed_eof()
        async for part in MultipartReader(request.headers, stream):  # type: ignore[misc]
            if isinstance(part, BodyPartReader) and part.name:
                if part.name == "flare_file":
                    tracer_flare[part.name] = base64.b64encode(await part.read()).decode("ascii")
                else:
                    tracer_flare[part.name] = await part.text()
    except Exception as err:
        tracer_flare["error"] = str(err)
    return tracer_flare
