import time
from typing import Any
from typing import List
from typing import cast
import urllib.parse

import requests

from ddapm_test_agent.trace import Trace


class TestAgentClient:
    __test__ = False

    def __init__(self, base_url: str):
        self._base_url = base_url
        self._session = requests.Session()

    def _url(self, path: str) -> str:
        return urllib.parse.urljoin(self._base_url, path)

    def traces(self, clear: bool = False, **kwargs: Any) -> List[Trace]:
        resp = self._session.get(self._url("/test/session/traces"), **kwargs)
        if clear:
            self.clear()
        json = resp.json()
        return cast(List[Trace], json)

    def requests(self, **kwargs: Any) -> List[Any]:
        resp = self._session.get(self._url("/test/session/requests"), **kwargs)
        json = resp.json()
        return cast(List[Any], json)

    def raw_telemetry(self, clear: bool = False) -> List[Any]:
        raw_reqs = self.requests()
        reqs = []
        for req in raw_reqs:
            if req["url"].endswith("/telemetry/proxy/api/v2/apmtelemetry"):
                reqs.append(req)
        if clear:
            self.clear()
        return reqs

    def telemetry(self, clear: bool = False, **kwargs: Any) -> List[Any]:
        resp = self._session.get(self._url("/test/session/apmtelemetry"), **kwargs)
        if clear:
            self.clear()
        return cast(List[Any], resp.json())

    def clear(self, **kwargs: Any) -> None:
        self._session.get(self._url("/test/session/clear"), **kwargs)

    def info(self, **kwargs):
        resp = self._session.get(self._url("/info"), **kwargs)
        json = resp.json()
        return json

    def wait_for_num_traces(self, num: int, clear: bool = False, wait_loops: int = 30) -> List[Trace]:
        """Wait for `num` traces to be received from the test agent.

        Returns after the number of traces has been received or raises otherwise after 2 seconds of polling.

        Returned traces are sorted by the first span start time to simplify assertions for more than one trace by knowing that returned traces are in the same order as they have been created.
        """
        num_received = 0
        traces = []
        for i in range(wait_loops):
            try:
                traces = self.traces(clear=False)
            except requests.exceptions.RequestException:
                pass
            else:
                num_received = len(traces)
                if num_received == num:
                    if clear:
                        self.clear()
                    return sorted(traces, key=lambda trace: trace[0]["start"])
            time.sleep(0.1)
        raise ValueError(
            "Number (%r) of traces not available from test agent, got %r:\n%r" % (num, num_received, traces)
        )

    def wait_for_num_spans(self, num: int, clear: bool = False, wait_loops: int = 30) -> List[Trace]:
        """Wait for `num` spans to be received from the test agent.

        Returns after the number of spans has been received or raises otherwise after 2 seconds of polling.

        Returned traces are sorted by the first span start time to simplify assertions for more than one trace by knowing that returned traces are in the same order as they have been created.
        """
        num_received = None
        for i in range(wait_loops):
            try:
                traces = self.traces(clear=False)
            except requests.exceptions.RequestException:
                pass
            else:
                num_received = 0
                for trace in traces:
                    num_received += len(trace)
                if num_received == num:
                    if clear:
                        self.clear()
                    return sorted(traces, key=lambda trace: trace[0]["start"])
            time.sleep(0.1)
        raise ValueError("Number (%r) of spans not available from test agent, got %r" % (num, num_received))

    def wait_for_telemetry_event(self, event_name: str, clear: bool = False, wait_loops: int = 200) -> Any:
        """Wait for and return the given telemetry event from the test agent."""
        for i in range(wait_loops):
            try:
                events = self.telemetry(clear=False)
            except requests.exceptions.RequestException:
                pass
            else:
                for event in events:
                    if event["request_type"] == "message-batch":
                        for message in event["payload"]:
                            if message["request_type"] == event_name:
                                if clear:
                                    self.clear()
                                return message
                    elif event["request_type"] == event_name:
                        if clear:
                            self.clear()
                        return event
            time.sleep(0.01)
        raise AssertionError("Telemetry event %r not found" % event_name)

    def wait_to_start(self, num_tries: int = 50, delay: float = 0.1) -> None:
        exc = []
        for i in range(num_tries):
            try:
                self.info()
            except requests.exceptions.RequestException as e:
                exc.append(e)
                time.sleep(delay)
            else:
                return
        raise AssertionError(f"Test agent did not start in time ({num_tries * delay} seconds). Got {exc[-1]}")
