# dbug-agent

## Prerequisites

You will need [Leiningen][] 2.0.0 or above installed.

[leiningen]: https://github.com/technomancy/leiningen

## Running

To start a web server for the application, run:

    lein ring server 8126

    lein ring server-headless 8126


## Packaging

To package as a jar:

    lein ring uberjar  # java -jar target/...jar
    # run the jar
    PORT=8126 java -jar target/dbug-agent-....jar

## Formatting

To format the code:

    lein cljfmt check
    lein cljfmt fix

## Tracer setup

```python
def snapshot(f):
    import json
    import pytest

    from ddtrace.compat import httplib
    from ddtrace import tracer

    def wrapper(*args, **kwargs):
        if len(args) == 1:
            self = args[0]

        test_id = "{}.{}.{}".format(__name__, self.__class__.__name__, f.__name__)
        try:
            tracer.writer.api._headers["X-Datadog-Test-Token"] = test_id
            return f(*args, **kwargs)
        finally:
            tracer.writer.flush_queue()
            del tracer.writer.api._headers["X-Datadog-Test-Token"]
            conn = httplib.HTTPConnection(tracer.writer.api.hostname, tracer.writer.api.port)
            conn.request("GET", "/test/snapshot", {}, {
                "X-Datadog-Test-Token": test_id,
            })
            r = conn.getresponse()
            if r.status != 200:
                msg = r.read().decode()
                pytest.fail(msg, pytrace=False)
    return wrapper
def snapshot(f):
    import json
    import pytest

    from ddtrace.compat import httplib
    from ddtrace import tracer

    def wrapper(*args, **kwargs):
        if len(args) == 1:
            self = args[0]

        test_id = "{}.{}.{}".format(__name__, self.__class__.__name__, f.__name__)
        conn = httplib.HTTPConnection(tracer.writer.api.hostname, tracer.writer.api.port)
        try:
            tracer.writer.api._headers["X-Datadog-Test-Token"] = test_id
            ret = f(*args, **kwargs)
            tracer.writer.flush_queue()
            conn.request("GET", "/test/snapshot", {}, {
                "X-Datadog-Test-Token": test_id,
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


## Features

### Sanity Checks

- Empty traces
- ID collisions
- Multiple root spans
- Inconsistent trace id in a trace
- Required metadata
- [TODO] All referenced spans exist
- [TODO] trace header validation


### Snapshot testing

- Trace matching


### TODO

- [ ] Flag for CI use (don't generate snapshots if they don't exist)
- [ ] Handle integration/language versioning if snapshots are expected to differ
