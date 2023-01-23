import argparse
import os
import sys

import requests
import yarl


def _add_token_arg(parser: argparse.ArgumentParser) -> None:
    """Add the test session token argument to the parser."""
    parser.add_argument(
        "--test-session-token",
        type=str,
        default=os.environ.get("TEST_SESSION_TOKEN"),
        help="Test session token to query with.",
    )


def _add_agent_url_arg(parser: argparse.ArgumentParser) -> None:
    """Add the agent url argument to the given parser."""
    parser.add_argument(
        "--agent-url",
        type=str,
        default=os.environ.get(
            "DD_TRACE_AGENT_URL",
            os.environ.get("DD_AGENT_URL", "http://localhost:8126"),
        ),
        help=("Test agent URL. Default is http://localhost:8126"),
    )


def main_session_start() -> None:
    """Entrypoint for the start-session command"""
    parser = argparse.ArgumentParser(
        description=(
            "Start a test agent session with a given token. "
            "All data submitted with this token will be associated with this session."
        ),
        prog="ddapm-test-agent-start-session",
    )
    _add_agent_url_arg(parser)
    _add_token_arg(parser)
    parsed_args = parser.parse_args(sys.argv[1:])
    url = yarl.URL(parsed_args.agent_url).with_path("/test/session/start")
    resp = requests.get(str(url), params={"test_session_token": parsed_args.test_session_token})
    if resp.status_code != 200:
        print(resp.text)
        sys.exit(1)
    print(resp.text)
    sys.exit(0)


def main_snapshot() -> None:
    """Entrypoint for the snapshot command"""
    parser = argparse.ArgumentParser(
        description=("Perform a snapshot test for the data received in the session."),
        prog="ddapm-test-agent-snapshot",
    )
    _add_agent_url_arg(parser)
    _add_token_arg(parser)
    parsed_args = parser.parse_args(sys.argv[1:])
    if not parsed_args.test_session_token:
        print(
            "Error: a test token is required! Please specify one with --test-session-token"
            " command line argument or the TEST_SESSION_TOKEN environment variable."
        )
        sys.exit(1)
    url = yarl.URL(parsed_args.agent_url).with_path("/test/session/snapshot")
    resp = requests.get(str(url), params={"test_session_token": parsed_args.test_session_token})
    if resp.status_code != 200:
        print(resp.text)
        sys.exit(1)
    print(resp.text)
    sys.exit(0)
