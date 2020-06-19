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

# TODO add ignore args to snapshot
def snapshot(f):
    import json
    import pytest

    from ddtrace.compat import httplib
    from ddtrace import tracer

    def wrapper(*args, **kwargs):
        # TODO: need class name here too
        test_id = "{}.{}".format(__name__, f.__name__)
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
```
