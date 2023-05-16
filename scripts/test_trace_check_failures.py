import asyncio
from functools import wraps
import sys

import aiohttp
import pytest

from ddapm_test_agent.agent import Agent
from ddapm_test_agent.agent import agent_instance


def mark_asyncio(f):
    """
    Test decorator that wraps a function so that it can be executed
    as an asynchronous coroutine. This uses the event loop set in the
    ``TestCase`` class, and runs the loop until it's completed.
    """

    @wraps(f)
    def wrapper(*args, **kwargs):
        if sys.version_info >= (3, 11):
            future = f(*args, **kwargs)
            loop = asyncio.get_event_loop()
            loop.run_until_complete(future)
            loop.close()
        else:
            coro = asyncio.coroutine(f)
            future = coro(*args, **kwargs)
            loop = asyncio.get_event_loop()
            loop.run_until_complete(future)
            loop.close()

    return wrapper


test_agent: Agent = agent_instance


def test_get_check_trace_failures():
    """Get the agent and check for any failures."""
    trace_failures = test_agent.get_check_trace_failures()

    if len(trace_failures) > 0:
        failure_message = f"APM Test Agent Validation failed with {len(trace_failures)} failures.\n"
        for check_trace_message in trace_failures:
            failure_message += check_trace_message
        return pytest.fail(text=failure_message)


@mark_asyncio
async def test_get_check_trace_failures_request():
    """Get the agent and check for any failures."""
    async with aiohttp.ClientSession() as session:
        async with session.get("http://localhost:8126/test/check_trace/failures") as resp:
            assert resp.status == 200, await resp.text()
