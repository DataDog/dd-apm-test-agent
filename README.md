# Datadog test agent

## Usage

### Local usage

```bash
docker pull kyleverhoog/dd-trace-test-agent

docker run --rm\
            -p 8126:8126\
            -e SNAPSHOT_DIR=/snaps\
            -v $HOME/dev/dd-trace-py/tests/snapshots:/snaps\
            kyleverhoog/dd-trace-test-agent:latest
```

### CI usage

See [Python](https://github.com/datadog/dd-trace-py).

## Checks

- Decoded properly
- Empty traces
- Span ID collisions
- Multiple root spans
- Circular references in spans
- Comparison against a reference (snapshot testing)
- [ ] Inconsistent trace id in a trace payload
- [ ] Required attributes
- [ ] All referenced spans exist
- [ ] Trace header validation
- [ ] Trace-logs correlation
- [ ] Tag size limit
- [ ] Type check on keys/values, eg. no strings in metrics


### TODO

- [ ] Warning mechanism - diff http response code?
- [ ] HTTPS support? (is this even supported in the real agent?)
- [ ] Feature flags to enable/disable checks
- [ ] Tests for the agent itself


## Overview

### /test/start

Initiate a _synchronous_ test case. All subsequent traces received will be
associated with the required test token provided.

#### [required] `?token=`

Test token for a test case. This must be unique across all test cases.


### /test/snapshot

#### ?token=

#### ?ignores=

#### ?dir=

Override the directory where the snapshot will be stored and retrieved from.
This directory must already exist.

Warning: it is an error to specify both `dir` and `file`.

#### ?file=

An absolute or relative (to the current working directory of the agent) file
name where the snap will be stored and retrieved.

Warning: it is an error to specify both `file` and `dir`.

#### X-Datadog-Test-Token

To run test cases in parallel this HTTP header must be specified. All test
cases sharing a test token will be grouped.


## Configuration

### Environment Variables

- `SNAPSHOT_DIR` [`"./snaps"`]: Directory in which snapshots will be stored.
    Can be overridden by providing the `dir` query param on `/snapshot`.

- `SNAPSHOT_CI` [`0`]: Toggles CI mode for the snapshotter. Set to `1` to
  enable. CI mode does the following:

  - When snapshots are _generated_ from a test case and there is no snapshot
    file a failure will be raised.


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
    PORT=8126 java -jar target/test-agent-....jar

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
docker run --rm --publish 8126:3000 agent:0.01
```


## Example: Python library usage

### Synchronous

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

            token = "{}{}{}.{}".format(__name__, "." if clsname else "", clsname, f.__name__)

            try:
                conn = httplib.HTTPConnection(tracer.writer.api.hostname, tracer.writer.api.port)
                conn.request("GET", "/test/start?token=%s" % token, {}, {})
                r = conn.getresponse()
                if r.status != 200:
                    raise ValueError("", r.read().decode())

                ret = f(*args, **kwargs)
                tracer.writer.flush_queue()

                ignoresqs = ",".join(ignores)
                conn = httplib.HTTPConnection(tracer.writer.api.hostname, tracer.writer.api.port)
                # TODO add file query param
                conn.request("GET", "/test/snapshot?ignores=%s&token=%s&file=out.snap&dir=snaps" % (ignoresqs, token), {}, {})
                r = conn.getresponse()
                if r.status != 200:
                    raise ValueError("", r.read().decode())
                return ret
            except ValueError as e:
                pytest.fail(e.args[1], pytrace=False)
            finally:
                conn.close()
        return wrapper
    return dec
```


### Parallel

```python
def snapshot(f):
    import pytest
    from ddtrace.compat import httplib
    from ddtrace import tracer

    def wrapper(*args, **kwargs):
        if len(args) == 1:
            self = args[0]

        token = "{}.{}.{}".format(__name__, self.__class__.__name__, f.__name__)
        conn = httplib.HTTPConnection(tracer.writer.api.hostname, tracer.writer.api.port)
        try:
            tracer.writer.api._headers["X-Datadog-Test-Token"] = token
            ret = f(*args, **kwargs)
            tracer.writer.flush_queue()
            conn.request("GET", "/test/snapshot", {}, {
                "X-Datadog-Test-Token": token,
            })
            r = conn.getresponse()
            if r.status != 200:
                msg = r.read().decode()
                pytest.fail(msg, pytrace=False)
            return ret
        finally:
            del tracer.writer.api._headers["X-Datadog-Test-Token"]
            conn.close()
    return wrapper
```
