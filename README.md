# Datadog APM test agent

Agent for Datadog APM libraries providing testing utilities.


## Installation

The test agent can be installed from PyPI, docker or from source.

From PyPI:

    pip install ddapm-test-agent

    ddapm-test-agent --port=8126


From Docker:

    # Run the test agent and mount the snapshot directory
    docker run --rm\
            -p 8126:8126\
            -e CI_MODE=0\
            -v $PWD/tests/snapshots:/snapshots\
            ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest


## Features

### Trace invariant checks

- HTTP headers
  - Trace count matches (`trace_count_header`)
  - Library version included (`meta_tracer_version_header`)
- Trace payload size (`trace_content_length`)
- [ ] Traces are non-empty
- [ ] Required span properties
- [ ] No collisions in trace ids across traces
- [ ] No collisions in span ids within a trace
- [ ] No multiple root spans
- [ ] No circular references in spans
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

The test agent provides a form of [characterization testing](https://en.wikipedia.org/wiki/Characterization_test) which
we refer to as snapshotting. This allows library maintainers to ensure that traces don't change unexpectedly when making
unrelated changes.

This can be used to write integration tests by having test cases use the tracer to emit traces which are collected by
the test agent and compared against reference traces stored previously.

To do snapshot testing with the test agent:

1. Ensure traces are associated with a session token (typically the name of the test case) by either:
   - Calling the `/test/session/start` with the token endpoint before emitting the traces; or
   - Attaching an additional query param or header specifying the session token on `/vX.Y/trace` requests (see below for
     the API specifics). (Required for concurrent test running)
2. Emit traces (run the integration test).
3. Signal the end of the session and perform the snapshot comparison by calling the `/tests/session/snapshot` endpoint
   with the session token. The endpoint will return a `400` response code if the snapshot failed along with a plain-text
   trace of the error which can be forwarded to the test framework to help triage the issue.

### TODO

- [ ] Check inconsistent trace id in a trace payload
- [ ] Required attributes
- [ ] All referenced spans exist

## API

### /test/traces

Return traces that have been received by the agent. Traces matching specific trace ids can be requested with the options
below.

#### [optional] `?trace_ids=`
#### [optional] `X-Datadog-Trace-Ids`

Specify trace ids as comma separated values (eg. `12345,7890,2468`)


### /test/session/start

Initiate a _synchronous_ session. All subsequent traces received will be
associated with the required test token provided.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

Test session token for a test case. **Ensure this value is unique to avoid conflicts between sessions.**


### /test/session/snapshot

#### [optional\*] `?test_session_token=`
#### [optional\*] `X-Datadog-Test-Session-Token`
To run test cases in parallel this HTTP header must be specified. All test
cases sharing a test token will be grouped.

\* Required for concurrent tests. Either via query param or HTTP header.

#### [optional] `?ignores=`

Comma-separated list of keys of which to ignore values for.

The default built-in ignore list is: `span_id`, `trace_id`, `parent_id`,
`duration`, `start`, `metrics.system.pid`, `meta.runtime-id`.


#### [optional] `?dir=`

default: `./snapshots` (relative to where the test agent is run).

Override the directory where the snapshot will be stored and retrieved from.
**This directory must already exist**.

This value will override the environment variable `SNAPSHOT_DIR`.

Warning: it is an error to specify both `dir` and `file`.

#### [optional] `?file=`

An absolute or relative (to the current working directory of the agent) file
name where the snap will be stored and retrieved.

Warning: it is an error to specify both `file` and `dir`.


### /test/session/traces

Return traces that have been received by the agent for the given session token.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`


## Configuration

### Environment Variables

- `PORT` [`8126`]: Port to listen on.

- `DISABLED_CHECKS` [`""`]: Comma-separated values of checks to disable.

- `LOG_LEVEL` [`"INFO"`]: Log level to use. DEBUG, INFO, WARNING, ERROR, CRITICAL.

- `LOG_SPAN_FMT` [`"[{name}]"`]: Format string to use when outputting spans in logs.

- `SNAPSHOT_DIR` [`"./snapshots"`]: Directory in which snapshots will be stored.
    Can be overridden by providing the `dir` query param on `/snapshot`.

- `SNAPSHOT_CI` [`0`]: Toggles CI mode for the snapshot tests. Set to `1` to
  enable. CI mode does the following:
  - When snapshots are unexpectedly _generated_ from a test case a failure will
    be raised.

- `SNAPSHOT_IGNORED_ATTRS` [`"span_id,trace_id,parent_id,duration,start,metrics.system.pid,meta.runtime-id"`]: The
   attributes to ignore when comparing spans in snapshots.


## Development

### Prerequisites

You will need Python 3.8 or above and `riot`. It is recommended to create a virtualenv:

    virtualenv --python=3.8 .venv
    source .venv/bin/activate
    pip install riot


### Running the tests

To run the tests (in Python 3.8):

    riot run -p3.8 test

### Linting and formatting

To lint and format the code:

    riot run -s flake8
    riot run -s fmt

### Docker

To build (and tag) the dockerfile:

```bash
docker build --tag testagent .
```

Run the tagged image:

```bash
docker run --rm -v ${PWD}/snaps:/snapshots --publish 8126:8126 agent
```


### Release notes

This project follows [`semver`](https://semver.org/) and so bug fixes, breaking
changes, new features, etc must be accompanied by a release note. To generate a
release note:

    riot run reno new <short-description-of-change>

document the changes in the generated file, remove the irrelevant sections and
commit the release note with the change.


### Releasing

1. Generate the release notes and use [`pandoc`](https://pandoc.org/) to format
them for Github:

    riot run -s reno report --no-show-source | pandoc -f rst -t gfm --wrap=none

    Copy the output and put them in a new release: https://github.com/DataDog/dd-apm-test-agent/releases/new.

2. Enter a tag for the release (following [`semver`](https://semver.org)).
3. Use the tag without the `v` as the title.
4. Save the release as a draft and pass the link to someone else to give a quick review.
5. If all looks good hit publish


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
                conn.request("GET", "/test/session/start?test_session_token=%s" % token, {}, {})

                # Run the test case.
                ret = f(*args, **kwargs)

                # Flush any generated traces so we don't have to wait.
                tracer.writer.flush_queue()

                ignoresqs = ",".join(ignores)
                conn = httplib.HTTPConnection(tracer.writer.api.hostname, tracer.writer.api.port)

                # Query for the results of the snapshot test
                conn.request("GET", "/test/session/snapshot?ignores=%s&test_session_token=%s&file=%s&dir=%s" % (ignoresqs, token, file, dir), {}, {})

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
