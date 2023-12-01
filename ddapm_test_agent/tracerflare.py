from asyncio import StreamReader
import base64
import typing
from typing import Dict
from typing import Mapping

import aiohttp
from aiohttp import MultipartReader


TracerFlareEvent = Dict[str, str]


async def v1_decode(headers: Mapping[str, str], data: bytes) -> TracerFlareEvent:
    """Decode v1 tracer flare form as a dict"""
    tracer_flare: TracerFlareEvent = {}
    try:
        stream = StreamReader()
        stream.feed_data(data)
        stream.feed_eof()
        async for part in MultipartReader(headers, typing.cast(aiohttp.StreamReader, stream)):
            if part.name is not None:
                if part.name == "flare_file":
                    tracer_flare[part.name] = base64.b64encode(await part.read()).decode("ascii")
                else:
                    tracer_flare[part.name] = await part.text()
    except Exception as err:
        tracer_flare["error"] = str(err)
    return tracer_flare
