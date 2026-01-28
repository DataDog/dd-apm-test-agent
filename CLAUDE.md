# dd-apm-test-agent

A test agent that emulates Datadog APM endpoints for testing client libraries. It receives traces, telemetry, metrics, and other data from tracers, providing endpoints for validation, snapshot testing, and local development.

## Quick Reference

```bash
# Activate virtual environment
source .venv/bin/activate

# Run the test agent
ddapm-test-agent --port=8126

# Run with web UI
ddapm-test-agent --port=8126 --web-ui-port=8080

# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_agent.py -v

# Run a single test
python -m pytest tests/test_agent.py::test_trace -v

# Create a release note
reno new <feature-name>

# Format snapshots
ddapm-test-agent-fmt path/to/snapshots

# Lint snapshots (check mode)
ddapm-test-agent-fmt --check path/to/snapshots
```

## Project Structure

```
ddapm_test_agent/           # Main package
  agent.py                  # Core application, routes, middleware (~95KB - main entry point)
  trace.py                  # Trace decoding and handling (v0.4, v0.5, v0.7 formats)
  trace_snapshot.py         # Snapshot comparison logic
  trace_checks.py           # Trace validation checks
  checks.py                 # Check framework infrastructure
  apmtelemetry.py           # APM telemetry event handling
  tracestats.py             # Trace statistics handling
  remoteconfig.py           # Remote configuration server
  logs.py                   # OTLP logs handling
  metrics.py                # OTLP metrics handling
  vcr_proxy.py              # VCR cassette recording/playback for 3rd party APIs
  llmobs_event_platform.py  # LLM Observability API endpoints
  client.py                 # Test client utilities
  fmt.py                    # Snapshot formatting CLI
  cmd.py                    # CLI entry points

tests/
  conftest.py               # Pytest fixtures (agent, payloads, helpers)
  test_agent.py             # Core agent endpoint tests
  test_snapshot.py          # Snapshot functionality tests
  test_trace.py             # Trace handling tests
  test_session.py           # Session management tests
  test_<module>.py          # Module-specific tests
  trace_utils.py            # Test utilities for trace generation

releasenotes/
  notes/                    # Reno release notes (YAML)
```

## Code Style

- **Formatter**: black (line length 120)
- **Import sorting**: isort (single line, google style)
- **Linting**: flake8
- **Type checking**: mypy (strict settings enabled in setup.cfg)

### Type Annotations

All functions require complete type annotations. The mypy config enforces:
- `disallow_incomplete_defs = true`
- `disallow_untyped_decorators = true`
- `warn_return_any = true`

```python
from typing import Any, Awaitable, Callable, Dict, List, Optional

async def handle_request(self, request: Request) -> web.Response:
    ...

def decode_payload(data: bytes, content_type: str) -> List[Dict[str, Any]]:
    ...
```

### Import Style

Imports are single-line, alphabetically ordered within groups:

```python
# Standard library
import asyncio
import json
import logging
from typing import Any
from typing import Dict
from typing import List
from typing import Optional

# Third party
from aiohttp import web
from aiohttp.web import Request
import msgpack

# Local
from ddapm_test_agent.trace import Span
from ddapm_test_agent.trace import Trace
```

## Testing

Tests use pytest with aiohttp's pytest plugin. The `agent` fixture provides a test client.

### Test Style

- No docstrings in simple test functions (docstrings allowed for complex parametrized tests)
- Concise assertions with helpful error messages
- Use existing fixtures from `conftest.py`
- Async tests for HTTP endpoints

```python
async def test_trace_put_v04(
    agent,
    v04_reference_http_trace_payload_headers,
    v04_reference_http_trace_payload_data,
):
    resp = await agent.put(
        "/v0.4/traces",
        headers=v04_reference_http_trace_payload_headers,
        data=v04_reference_http_trace_payload_data,
    )
    assert resp.status == 200, await resp.text()


async def test_info(agent):
    resp = await agent.get("/info")
    assert resp.status == 200
    data = await resp.json()
    assert "version" in data
    assert "endpoints" in data
```

### Key Fixtures (from conftest.py)

- `agent` - aiohttp test client connected to the test agent
- `v04_reference_http_trace_payload_data` - Sample v0.4 trace payload (msgpack)
- `v04_reference_http_trace_payload_headers` - Headers for trace requests
- `do_reference_v04_http_trace` - Helper function to send trace requests
- `snapshot_dir` - Temporary directory for snapshot tests
- `testagent` - Full subprocess test agent for integration tests

### Running Tests

```bash
# All tests
python -m pytest tests/ -v

# Specific file
python -m pytest tests/test_agent.py -v

# Single test
python -m pytest tests/test_snapshot.py::test_snapshot_single_trace -v

# With coverage
python -m pytest tests/ --cov=ddapm_test_agent
```

## Key Concepts

### Session Tokens

Requests can be associated with a test session using tokens:
- Query param: `?test_session_token=my_test`
- Header: `X-Datadog-Test-Session-Token: my_test`

### Trace Formats

The agent supports multiple trace formats:
- v0.4: Standard msgpack format (most common)
- v0.5: Optimized format with string interning
- v0.7: Latest format with additional features
- v1: Legacy format

### Snapshot Testing

Characterization testing for traces:
1. Send traces to the agent
2. Call `/test/session/snapshot` to generate/compare snapshots
3. Snapshots are normalized JSON files

### VCR Proxy

Record and replay 3rd party API calls:
- Endpoint: `/vcr/{provider}/...`
- Supports: OpenAI, Azure OpenAI, Anthropic, AWS Bedrock, etc.
- Cassettes stored in `vcr-cassettes/` directory

## Adding New Endpoints

1. Add handler method to appropriate module (or `agent.py` for core endpoints)
2. Register route in `make_app()` or module's `get_routes()` method
3. Add tests following existing patterns
4. Create release note: `reno new <feature-name>`

### Handler Pattern

```python
async def handle_my_endpoint(self, request: Request) -> web.Response:
    token = _session_token(request)
    body = await request.json()

    # Process request...

    return web.json_response({"status": "ok"})
```

### Route Registration (in agent.py)

```python
# In make_app() function
app.router.add_route("GET", "/my/endpoint", agent.handle_my_endpoint)
app.router.add_route("POST", "/my/endpoint", agent.handle_my_endpoint)
```

## Release Notes

Use reno for release notes:

```bash
reno new my-feature-name
```

Edit the generated file in `releasenotes/notes/`:

```yaml
---
features:
  - |
    Add new endpoint for X functionality.
```

Keep release notes concise (1-3 sentences).

## Common Patterns

### Decoding Payloads

```python
import msgpack

# msgpack (most trace payloads)
data = msgpack.unpackb(await request.read(), raw=False)

# JSON
data = await request.json()

# With content-type detection
content_type = request.content_type
if "msgpack" in content_type:
    data = msgpack.unpackb(await request.read(), raw=False)
else:
    data = await request.json()
```

### Session-Aware Data Access

```python
def _requests_by_session(self, token: Optional[str]) -> List[Request]:
    if token is None:
        return self._requests
    return [r for r in self._requests if r.get("token") == token]
```

### Middleware Pattern

```python
from aiohttp.web import middleware

@middleware
async def my_middleware(request: Request, handler: _Handler) -> web.Response:
    # Pre-processing
    response = await handler(request)
    # Post-processing
    return response
```

## Environment Variables

Key configuration options (see README.md for full list):

- `PORT` - HTTP port (default: 8126)
- `SNAPSHOT_DIR` - Snapshot storage directory
- `SNAPSHOT_CI` - Enable CI mode (fail if snapshot missing)
- `ENABLED_CHECKS` - Comma-separated list of trace checks
- `DD_AGENT_URL` - Proxy to real Datadog agent
- `LOG_LEVEL` - Logging level (DEBUG, INFO, WARNING, ERROR)
- `VCR_CASSETTES_DIRECTORY` - VCR cassette storage path
