# Datadog test agent

A test agent for APM integration libraries.

## Usage

### Local usage

```bash
# Pull the image
docker pull kyleverhoog/dd-trace-test-agent

# Run the test agent and mount the snapshot directory
docker run --rm\
            -p 8126:8126\
            -e SNAPSHOT_DIR=/snaps\
            -v $HOME/dev/dd-trace-py/tests/snapshots:/snaps\
            kyleverhoog/dd-trace-test-agent:latest
```

### CI usage

See the [Python library PR](https://github.com/datadog/dd-trace-py/pull/1546).

## Features

### Trace invariant checks

- Decoding
- HTTP headers
  - Trace count matches
- [ ] Traces are non-empty
- [ ] Required span properties
- [ ] No collisions in trace ids across traces
- No collisions in span ids within a trace
- No multiple root spans
- No circular references in spans
- [ ] Tags are within the permitted size limits
- [ ] Type checks
  - Span properties
    - IDs are 64-bit integers
  - All keys are strings
  - Values in metrics are numeric
  - Values in meta are string or numeric
- [ ] No duplicate values between meta and metrics
- [ ] All referenced spans exist
- [ ] Value checks
  - Sampling tags
- [ ] Span type checks
  - eg. "type: redis" has "host" and "port" tags in meta
  - eg. "type: web" has resource


### Snapshot testing


### TODO

- [ ] Check inconsistent trace id in a trace payload
- [ ] Required attributes
- [ ] All referenced spans exist
- [ ] Trace-logs correlation
- [ ] Warning mechanism - diff http response code?
- [ ] HTTPS support? (is this even supported in the real agent?)
- [ ] Feature flags to enable/disable checks (eg. E001, W001); be able to pass
      these with requests.
- [ ] Better error messages for trace shape
- [ ] Better error messages for span diff
- [ ] Endpoint to fetch the traces for continued testing in the library


## Overview

### /test/start

Initiate a _synchronous_ test case. All subsequent traces received will be
associated with the required test token provided.

#### [required] `?token=`

Test token for a test case. This must be unique across all test cases.


### /test/snapshot

#### [optional\*] `?token=`
#### [optional\*] `X-Datadog-Test-Token`
To run test cases in parallel this HTTP header must be specified. All test
cases sharing a test token will be grouped.

\* Required for concurrent tests. Either via query param or HTTP header.

#### [optional] `?ignores=`

Comma-separated list of keys of which to ignore values for.

The base built-in ignore list is: `span_id`, `trace_id`, `parent_id`,
`duration`, `start`, `metrics.system.pid`, `meta.runtime-id`.


#### [optional] `?dir=`

default: `./snaps` (relative to the test agent executable).

Override the directory where the snapshot will be stored and retrieved from.
**This directory must already exist**.

This value will override the environment variable `SNAPSHOT_DIR`.

Warning: it is an error to specify both `dir` and `file`.

#### [optional] `?file=`

An absolute or relative (to the current working directory of the agent) file
name where the snap will be stored and retrieved.

Warning: it is an error to specify both `file` and `dir`.


## Configuration

### Environment Variables

- `SNAPSHOT_DIR` [`"./snaps"`]: Directory in which snapshots will be stored.
    Can be overridden by providing the `dir` query param on `/snapshot`.

- `SNAPSHOT_CI` [`0`]: Toggles CI mode for the snapshot tests. Set to `1` to
  enable. CI mode does the following:

  - When snapshots are unexpectedly _generated_ from a test case a failure will
    be raised.

- `DD_TEST_AGENT_PORT` [`8126`]: Port to listen on.


## Development

### Prerequisites

You will need [Leiningen][] 2.0.0 or above installed.

[leiningen]: https://github.com/technomancy/leiningen

### Running

To start a web server for the application, run:

    lein ring server 8126

    lein ring server-headless 8126


### Packaging

To package as a jar:

    lein ring uberjar  # java -jar target/...jar
    # run the jar
    java -jar target/test-agent-....jar

### Formatting

To format the code:

    lein cljfmt check
    lein cljfmt fix

### Docker

To build (and tag) the dockerfile:

```bash
docker build --tag agent:0.01 .
```

Run the tagged image:

```bash
docker run --rm --publish 8126:8126 agent:0.01
```


## Example: Python library usage

### Synchronous

For synchronous usage we simply need to tell the test agent when a test case
has started and then when it's done, query the results.

```python
def snapshot(ignores=None, file=None, dir=None):
    import pytest
    from ddtrace.compat import httplib
    from ddtrace import tracer

    ignores = ignores or []

    def dec(f):

        def wrapper(*args, **kwargs):
            if len(args) > 1:
                self = args[0]
                clsname = self.__class__.__name__
            else:
                clsname = ""

            # Unique test token for this test case: the fully qualified test name.
            token = "{}{}{}.{}".format(__name__, "." if clsname else "", clsname, f.__name__)

            try:
                # Connection to the test agent.
                conn = httplib.HTTPConnection(tracer.writer.api.hostname, tracer.writer.api.port)

                # Signal the start of this test case.
                conn.request("GET", "/test/start?token=%s" % token, {}, {})

                # Run the test case.
                ret = f(*args, **kwargs)

                # Flush any generated traces so we don't have to wait.
                tracer.writer.flush_queue()

                ignoresqs = ",".join(ignores)
                conn = httplib.HTTPConnection(tracer.writer.api.hostname, tracer.writer.api.port)

                # Query for the results of the snapshot test
                conn.request("GET", "/test/snapshot?ignores=%s&token=%s&file=%s&dir=%s" % (ignoresqs, token, file, dir), {}, {})

                # If we get a non-200 response code the test failed.
                r = conn.getresponse()
                if r.status != 200:
                    # A plain-text message is included in the body which can be
                    # presented to the user.
                    pytest.fail(r.read().decode(), pytrace=False)

                return ret
            finally:
                conn.close()
        return wrapper
    return dec
```


### Parallel

The parallel configuration involves attaching a test token HTTP header to every
request to the agent.

```python
def snapshot(f):
    import pytest
    from ddtrace.compat import httplib
    from ddtrace import tracer

    def wrapper(*args, **kwargs):
        if len(args) == 1:
            self = args[0]

        # Unique test token for this test case: the fully qualified test name.
        token = "{}.{}.{}".format(__name__, self.__class__.__name__, f.__name__)

        # Connection for querying the test agent.
        conn = httplib.HTTPConnection(tracer.writer.api.hostname, tracer.writer.api.port)

        try:
            # Patch the tracer writer to include the test token header.
            tracer.writer.api._headers["X-Datadog-Test-Token"] = token

            # Run the test.
            ret = f(*args, **kwargs)

            # Flush any generated traces so we don't have to wait.
            tracer.writer.flush_queue()

            # Query for the results of the snapshot test.
            conn.request("GET", "/test/snapshot", {}, {
                "X-Datadog-Test-Token": token,
            })

            # If we get a non-200 response code the test failed.
            r = conn.getresponse()
            if r.status != 200:
                # A plain-text message is included in the body which can be
                # presented to the user.
                msg = r.read().decode()
                pytest.fail(msg, pytrace=False)
            return ret
        finally:
            # Clear the http header.
            del tracer.writer.api._headers["X-Datadog-Test-Token"]
            conn.close()
    return wrapper
```
