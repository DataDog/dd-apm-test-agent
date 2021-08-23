from typing import List

from .trace import Trace


class Snapshot:
    def __init__(
        self, expected_traces: List[Trace], received_traces: List[Trace]
    ) -> None:
        pass
