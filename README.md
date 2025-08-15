# Datadog APM test agent

[![GitHub Workflow Status (with branch)](https://img.shields.io/github/actions/workflow/status/DataDog/dd-apm-test-agent/main.yml?style=flat-square)](https://github.com/DataDog/dd-apm-test-agent/actions?query=workflow%3ACI+branch%3Amaster)
[![PyPI](https://img.shields.io/pypi/v/ddapm-test-agent?style=flat-square)](https://pypi.org/project/ddapm-test-agent/)


<img align="right" src="https://user-images.githubusercontent.com/6321485/136316621-b4af42b6-4d1f-4482-a45b-bdee47e94bb8.jpeg" alt="bits agent" width="200px"/>

The APM test agent is an application which emulates the APM endpoints of the [Datadog agent](https://github.com/DataDog/datadog-agent/) which can be used for testing Datadog APM client libraries.

See the [Features](#features) section for the complete list of functionalities provided.

See the [HTTP API](#http-api) section for the endpoints available.

See the [Development](#development) section for how to get the test agent running locally to add additional checks or fix bugs.


## Installation

The test agent can be installed using [nix](https://docs.determinate.systems/getting-started/):

    nix profile install github:datadog/dd-apm-test-agent#ddapm-test-agent
    # nix profile upgrade ddapm-test-agent # to upgrade

The test agent can be installed from PyPI:

    pip install ddapm-test-agent

    # HTTP on port 8126, OTLP HTTP on port 4318, OTLP GRPC on port 4317
    ddapm-test-agent --port=8126 --otlp-http-port=4318 --otlp-grpc-port=4317

or from Docker:

    # Run the test agent and mount the snapshot directory
    docker run --rm\
            -p 8126:8126\
            -p 4318:4318\
            -p 4317:4317\
            -e SNAPSHOT_CI=0\
            -v $PWD/tests/snapshots:/snapshots\
            ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest

or from source:

    pip install git+https://github.com/Datadog/dd-apm-test-agent

or a specific branch:

    pip install git+https://github.com/Datadog/dd-apm-test-agent@{branch}


## Features

### Trace invariant checks

Many checks are provided by the test agent which will verify trace data.
All checks are enabled by default and can be manually disabled.

See the [configuration](#configuration) section for the options.

| Check description  | Check name |
| ------------- | ------------- |
| Trace count header matches number of traces  | `trace_count_header`  |
| Client library version header included in request  | `meta_tracer_version_header`  |
| Trace content length header matches payload size  | `trace_content_length`  |


### Returning data

All data that is submitted to the test agent can be retrieved.

- Traces can be returned via the `/test/traces` endpoint documented [below](#api).


### Helpful logging

The `INFO` log level of the test agent outputs useful information about the requests the test agent receives. For traces this includes a visual representation of the traces.

```
INFO:ddapm_test_agent.agent:received trace payload with 1 trace chunk
INFO:ddapm_test_agent.agent:Chunk 0
[parent]
├─ [child1]
├─ [child2]
└─ [child3]
INFO:ddapm_test_agent.agent:end of payload ----------------------------------------
```


### Proxy

The test agent provides proxying to the Datadog agent.
This is enabled by passing the agent url to the test agent either via the `--agent-url` command-line argument or by the `DD_TRACE_AGENT_URL` or `DD_AGENT_URL` environment variables.

When proxying is enabled, the response from the Datadog agent will be returned instead of one from the test agent.

At the trace-level, proxying can also be disabled by including the `X-Datadog-Agent-Proxy-Disabled` header with a value of `true`. This will disable proxying after a trace
is handled, regardless of whether an agent URL is set.


### Snapshot testing

The test agent provides a form of [characterization testing](https://en.wikipedia.org/wiki/Characterization_test) which
we refer to as snapshotting.
This allows library maintainers to ensure that traces don't change unexpectedly when making unrelated changes.

This can be used to write integration tests by having test cases use the tracer to emit traces which are collected by the test agent and compared against reference traces stored previously.

To do snapshot testing with the test agent:

1. Ensure traces are associated with a session token (typically the name of the test case) by either:
   - Calling the `/test/session/start` with the token endpoint before emitting the traces; or
   - Attaching an additional query string parameter or header specifying the session token on `/vX.Y/trace` requests (see below for
     the API specifics). (Required for concurrent test running)
2. Emit traces (run the integration test).
3. Signal the end of the session and perform the snapshot comparison by calling the `/tests/session/snapshot` endpoint
   with the session token. The endpoint will return a `400` response code if the snapshot failed along with a plain-text
   trace of the error which can be forwarded to the test framework to help triage the issue.


#### Snapshot output

The traces are normalized and output in JSON to a file. The following transformations are made to the input:

- Trace ids are overwritten to match the order in which the traces were received.
- Span ids are overwritten to be the DFS order of the spans in the trace tree.
- Parent ids are overwritten using the normalized span ids. However, if the parent is not a span in the trace, the parent id is not overwritten. This is necessary for handling distributed traces where all spans are not sent to the same agent.
- Span attributes are ordered to be more human-readable, with the important attributes being listed first.
- Span attributes are otherwise ordered alphanumerically.
- The span meta and metrics maps if empty are excluded.


### Recording 3rd party API requests

The test agent can be configured to proxy requests to select provider API endpoints, capturing real requests to
the server and recording them to play back for future use. Currently, only OpenAI, Azure OpenAI, and DeepSeek are supported.

These cassettes are recorded by default in the `vcr-cassettes` directory. However, this can be changed with the `--vcr-cassettes-directory` command-line option, or `VCR_CASSETTES_DIRECTORY` environment variable.

The cassettes are matched based on the path, method, and body of the request. To mount a cassette directory when running the test agent in a Docker container, run the container with

    docker run --rm\
            -p 8126:8126\
            -v $PWD/vcr-cassettes:/vcr-cassettes
            ghcr.io/datadog/dd-apm-test-agent/ddapm-test-agent:latest

Optionally specifying whatever mounted path is used for the cassettes directory. The test agent comes with a default set of cassettes for OpenAI, Azure OpenAI, and DeepSeek.

#### Usage in clients

To use this feature in your client, you can use the `/vcr/{provider}` endpoint to proxy requests to the provider API.

```python
from openai import OpenAI

client = OpenAI(base_url="http://127.0.0.1:9126/vcr/openai")
```

#### Recording test names as part of VCR cassette names
The test agent has two endpoints to configure a context around which any VCR cassettes recorded have a suffix of a given test name. To use this, you can hit the
- `/vcr/test/start` with a `test_name` body field to set the test name
- `/vcr/test/stop` to clear the test name

This is useful for recording cassettes for a specific test case to easily associate cassettes with that test.

Usage example:

```python
@pytest.mark.fixture
def with_vcr_test_name(request):
  with requests.post("http://127.0.0.1:9126/vcr/test/start", json={"test_name": request.node.name}):
    yield
  requests.post("http://127.0.0.1:9126/vcr/test/stop")

@pytest.mark.fixture
def openai_with_custom_url(with_vcr_test_name):
  client = OpenAI(base_url="http://127.0.0.1:9126/vcr/openai")
  yield client

def test_openai_with_custom_url(openai_with_custom_url):
  """This test will generate/use a cassette name something similar to `openai_chat_completions_post_abcd1234_test_openai_with_custom_url`"""
  ...
```

#### Adding new providers

To add a new provider, add a supported provider in the `PROVIDER_BASE_URLS` dictionary in `ddapm_test_agent/vcr_proxy.py`, and change your tests or use case to use the new provider in the base url:

```python
base_url = "http://127.0.0.1:9126/vcr/{new_provider}"
```

And pass in a valid API key (if needed) in the way that provider expects.

To redact api keys, modify the `filter_headers` list in the `get_vcr` function in `ddapm_test_agent/vcr_proxy.py`. This can be confirmed by viewing cassettes in the `vcr-cassettes` directory (or the otherwise specified directory), and verifying that any new cassettes do not contain the api key.

## Configuration

The test agent can be configured via command-line options or via environment variables.

### Command line

#### ddapm-test-agent

`ddapm-test-agent` is command used to run a test agent.

Please refer to `ddapm-test-agent --help` for more information.

#### ddapm-test-agent-fmt

`ddapm-test-agent-fmt` is a command line tool to format or lint snapshot json files.

``` bash
# Format all snapshot json files
ddapm-test-agent-fmt path/to/snapshots

# Lint snapshot json files
ddapm-test-agent-fmt --check path/to/snapshots
```

Please refer to `ddapm-test-agent-fmt --help` for more information.

### Environment Variables

- `PORT` [`8126`]: Port to listen on.

- `ENABLED_CHECKS` [`""`]: Comma-separated values of checks to enable. Valid values can be found in [trace invariant checks](#trace-invariant-checks)

- `LOG_LEVEL` [`"INFO"`]: Log level to use. DEBUG, INFO, WARNING, ERROR, CRITICAL.

- `LOG_SPAN_FMT` [`"[{name}]"`]: Format string to use when outputting spans in logs.

- `SNAPSHOT_DIR` [`"./snapshots"`]: Directory in which snapshots will be stored.
  Can be overridden by providing the `dir` query parameter on `/snapshot`.

- `SNAPSHOT_CI` [`0`]: Toggles CI mode for the snapshot tests. Set to `1` to
  enable. CI mode does the following:
    - When snapshots are unexpectedly _generated_ from a test case a failure will
      be raised.

- `SNAPSHOT_IGNORED_ATTRS` [`"span_id,trace_id,parent_id,duration,start,metrics.system.pid,metrics.process_id,metrics.system.process_id,meta.runtime-id"`]: The
  attributes to ignore when comparing spans in snapshots.

- `DD_AGENT_URL` [`""`]: URL to a Datadog agent. When provided requests will be proxied to the agent.

- `DD_APM_RECEIVER_SOCKET` [`""`]: When provided, the test agent will listen for traces on a socket at the path provided (e.g., `/var/run/datadog/apm.socket`)

- `DD_SUPPRESS_TRACE_PARSE_ERRORS` [`false`]: Set to `"true"` to disable span parse errors when decoding handled traces. When disabled, errors will not be thrown for
metrics incorrectly placed within the meta field, or other type errors related to span tag formatting/types. Can also be set using the `--suppress-trace-parse-errors=true` option.

- `SNAPSHOT_REMOVED_ATTRS` [`""`]: The attributes to remove from spans in snapshots. This is useful for removing attributes
that are not relevant to the test case. **Note that removing `span_id` is not permitted to allow span
ordering to be maintained.**

- `SNAPSHOT_REGEX_PLACEHOLDERS` [`""`]: The regex expressions to replace by a placeholder. Expressed as a comma separated `key:value` list. Specifying `ba[rz]:placeholder` will change any occurrence of `bar` or `baz` to `{placeholder}`: `foobarbazqux` -> `foo{placeholder}{placeholder}qux`. This is in particular useful to strip path prefixes or other infrastructure dependent identifiers.

- `DD_POOL_TRACE_CHECK_FAILURES` [`false`]: Set to `"true"` to pool Trace Check failures that occured within Test-Agent memory. These failures can be queried later using the `/test/trace_check/failures` endpoint. Can also be set using the `--pool-trace-check-failures=true` option.

- `DD_DISABLE_ERROR_RESPONSES` [`false`]: Set to `"true"` to disable Test-Agent `<Response 400>` when a Trace Check fails, instead sending a valid `<Response 200>`. Recommended for use with the `DD_POOL_TRACE_CHECK_FAILURES` env variable. Can also be set using the `--disable-error-responses=true` option.


## HTTP API

### /test/traces

Return traces that have been received by the agent. Traces matching specific trace ids can be requested with the options
below.

#### [optional] `?trace_ids=`
#### [optional] `X-Datadog-Trace-Ids`

Specify trace ids as comma separated values (eg. `12345,7890,2468`)


### /test/session/start

Initiate a _synchronous_ session. All subsequent traces received will be
associated with the required test token provided.

#### [optional] `?agent_sample_rate_by_service=`

Sample rates to be returned by the agent in response to trace v0.4 and v0.5 requests.

Example: `"{'service:test,env:staging': 0.5, 'service:test2,env:prod': 0.2}"` (note the JSON has to be URL-encoded).

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

Test session token for a test case. **Ensure this value is unique to avoid conflicts between sessions.**


### /test/session/snapshot

Perform a snapshot generation or comparison on the data received during the session.

Snapshots are generated when the test agent is not in CI mode and there is no snapshot file present. Otherwise a
snapshot comparison will be performed.


#### [optional\*] `?test_session_token=`
#### [optional\*] `X-Datadog-Test-Session-Token`
To run test cases in parallel this HTTP header must be specified. All test
cases sharing a test token will be grouped.

\* Required for concurrent tests. Either via query param or HTTP header.

#### [optional] `?ignores=`

Comma-separated list of keys of which to ignore values for.

The default built-in ignore list is: `span_id`, `trace_id`, `parent_id`,
`duration`, `start`, `metrics.system.pid`, `metrics.process_id`,
`metrics.system.process_id`, `meta.runtime-id`.


#### [optional] `?dir=`

default: `./snapshots` (relative to where the test agent is run).

Override the directory where the snapshot will be stored and retrieved from.
**This directory must already exist**.

This value will override the environment variable `SNAPSHOT_DIR`.

Warning: it is an error to specify both `dir` and `file`.

#### [optional] `?file=`
#### [optional] `X-Datadog-Test-Snapshot-Filename`

An absolute or relative (to the current working directory of the agent) file
name where the snap will be stored and retrieved.

Warning: it is an error to specify both `file` and `dir`.

Note: the file extension will be appended to the filename.

`_tracestats` will be appended to the filename for trace stats requests.

#### [optional] `?removes=`

Comma-separated list of keys that will be removed from spans in the snapshot.

The default built-in remove list does not remove any keys.


### /test/session/requests

Return all requests that have been received by the agent for the given session token.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

Returns the requests in the following json format:

```json
[
  {
    "headers": {},
    "body": "...",
    "url": "http...",
    "method": "GET"
  }
]
```

`body` is a base64 encoded body of the request.

### /test/session/traces

Return traces that have been received by the agent for the given session token.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`


### /test/session/stats

Return stats that have been received by the agent for the given session token.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

Stats are returned as a JSON list of the stats payloads received.

### /test/session/logs

Return OpenTelemetry logs that have been received by the agent for the given session token.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

Logs are returned as a JSON list of the OTLP logs payloads received. The logs are in the standard OpenTelemetry Protocol (OTLP) v1.7.0 format, decoded from protobuf into JSON.

### /test/session/metrics

Return OpenTelemetry metrics that have been received by the agent for the given session token.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

Metrics are returned as a JSON list of the OTLP metrics payloads received. The metrics are in the standard OpenTelemetry Protocol (OTLP) v1.7.0 format, decoded from protobuf into JSON.

### /test/session/responses/config (POST)
Create a Remote Config payload to retrieve in endpoint `/v0.7/config`

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

```
curl -X POST 'http://0.0.0.0:8126/test/session/responses/config' -d '{"roots": ["eyJ....fX0="], "targets": "ey...19", "target_files": [{"path": "datadog/2/ASM_DATA/blocked_users/config", "raw": "eyJydWxlc19kYXRhIjogW119"}], "client_configs": ["datadog/2/ASM_DATA/blocked_users/config"]}'
```

### /test/session/responses/config/path (POST)
Due to Remote Config payload being quite complicated, this endpoint works like `/test/session/responses/config (POST)`
but you should send a path and a message and this endpoint builds the Remote Config payload.

The keys of the JSON body are `path` and `msg`

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

```
curl -X POST 'http://0.0.0.0:8126/test/session/responses/config/path' -d '{"path": "datadog/2/ASM_DATA/blocked_users/config", "msg": {"rules_data": []}}'
```


### /test/trace_check/failures (GET)
Get Trace Check failures that occured. If a token is included, trace failures for only that session token are returned unless used in conjuction with `return_all`, which can be used to return all failures regardless of inputted token.  This method returns a `<Response 200>` if no Trace Check failures are being returned and a `<Response 400>` if Trace Check failures are being returned. Trace Check failures are returned as a content type of text, with failure messages concatenated in the response body. Optionally, set the `use_json` query string parameter to `true` to return Trace Check failures as a JSON response in the following format:
```
response = {
  "<FAILING_CHECK_NAME>" : ["<FAILURE_MESSAGE_1>", "<FAILURE_MESSAGE_2>"]
}
```

NOTE: To be used in combination with `DD_POOL_TRACE_CHECK_FAILURES`, or else failures will not be saved within Test-Agent memory and a `<Response 200>` will always be returned.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`
#### [optional] `?use_json=`
#### [optional] `?return_all=`

```
curl -X GET 'http://0.0.0.0:8126/test/trace_check/failures'
```

### /test/trace_check/clear (GET)
Clear Trace Check failures that occured. If a token is included, trace failures for only that session token are cleared unless used in conjuction with `clear_all`. This argument can be used to clear all failures (regardless of inputted session token).

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`
#### [optional] `?clear_all=`

```
curl -X GET 'http://0.0.0.0:8126/test/trace_check/clear'
```

### /test/trace_check/summary (GET)
Get Trace Check summary results. If a token is included, returns summary results only for Trace Checks run during the session.  The `return_all` optional query string parameter can be used to return all trace check results (regardless of inputted session token). The method returns Trace Check results in the following JSON format:
```
summary = {
  "trace_content_length" : {
    "Passed_Checks": 10,
    "Failed_Checks": 0,
    "Skipped_Checks": 4,
  }  ...
}
```

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`
#### [optional] `?return_all=`

```
curl -X GET 'http://0.0.0.0:8126/test/trace_check/summary'
```

### /test/session/integrations (PUT)
Update information about the current tested integration.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

```
curl -X PUT 'http://0.0.0.0:8126/test/session/integrations' -d '{"integration_name": [INTEGRATION_NAME], "integration_version": [INTEGRATION_VERSION],
"dependency_name": [DEPENDENCY_NAME], "tracer_language": [TRACER_LANGUAGE], "tracer_version": [TRACER_VERSION]}'
```

### /test/integrations/tested_versions (GET)
Return a csv list of all tested integrations received by the agent. The format of returned data will be:
`tracer_language,tracer_version,integration_name,integration_version,dependency_name`.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

```
curl -X GET 'http://0.0.0.0:8126/test/integrations/tested_versions'
```

### /v0.1/pipeline_stats

Mimics the pipeline_stats endpoint of the agent, but always returns OK, and logs a line everytime it's called.

### /v1/logs (HTTP)

Accepts OpenTelemetry Protocol (OTLP) v1.7.0 logs in protobuf format via HTTP. This endpoint validates and decodes OTLP logs payloads for testing OpenTelemetry logs exporters and libraries.

The HTTP endpoint accepts `POST` requests with `Content-Type: application/x-protobuf` and `Content-Type: application/json` and stores the decoded logs for retrieval via the `/test/session/logs` endpoint.

### /v1/metrics (HTTP)

Accepts OpenTelemetry Protocol (OTLP) v1.7.0 metrics in protobuf format via HTTP. This endpoint validates and decodes OTLP metrics payloads for testing OpenTelemetry metrics exporters and libraries.

The HTTP endpoint accepts `POST` requests with `Content-Type: application/x-protobuf` and `Content-Type: application/json` and stores the decoded metrics for retrieval via the `/test/session/metrics` endpoint.

### OTLP Logs and Metrics via GRPC

OTLP logs and metrics can also be sent via GRPC using the OpenTelemetry `LogsService.Export` and `MetricsService.Export` methods respectively. The GRPC server implements the standard OTLP service interfaces and forwards all requests to the HTTP server, ensuring consistent processing and session management.

**Note:** OTLP endpoints are served on separate ports from the main APM endpoints (default: 8126):
- **HTTP**: Port 4318 (default) - Use `--otlp-http-port` to configure
- **GRPC**: Port 4317 (default) - Use `--otlp-grpc-port` to configure

Both protocols store decoded data for retrieval via the `/test/session/logs` and `/test/session/metrics` HTTP endpoints respectively.

GRPC Client → GRPC Server → HTTP POST → HTTP Server → Agent Storage
                    ↓                                      ↓
            (forwards protobuf)                    (session management)
                    ↓                                      ↓
                   HTTP                              Retrievable via
                Response                     /test/session/{logs,metrics}

### /tracer_flare/v1

Mimics the tracer_flare endpoint of the agent. Returns OK if the flare contains the required form fields, otherwise `400`.

Logs a line everytime it's called and stores the tracer flare details in the request under `"_tracer_flare"`.

### /test/session/tracerflares

Return all tracer-flares that have been received by the agent for the given session token.

#### [optional] `?test_session_token=`
#### [optional] `X-Datadog-Test-Session-Token`

Returns the tracer-flares in the following json format:

```json
[
  {
    "source": "...",
    "case_id": "...",
    "email": "...",
    "hostname": "...",
    "flare_file": "...",
  }
]
```

`flare_file` is the base64 encoded content of the tracer-flare payload.

If there was an error parsing the tracer-flare form, that will be recorded under `error`.

### /test/settings (POST)

Allows to change some settings on the fly.
This endpoint takes a POST request with a json content listing the keys and values to apply.

```js
{ 'key': value }
```

Supported keys:
 - `trace_request_delay`: sets a delay to apply to trace and telemetry requests

 ```
curl -X POST 'http://0.0.0.0:8126/test/settings' -d '{ "trace_request_delay": 5 }'
```

## Development

### Prerequisites

A Python version of 3.8 or above and [`riot`](https://github.com/Datadog/riot) are required. It is recommended to create
and work out of a virtualenv:

    python3.12 -m venv .venv
    source .venv/bin/activate
    pip install -e '.[testing]'


### Running the tests

To run the tests (in Python 3.12):

    riot run -p3.12 test

Note: if snapshots need to be (re)generated in the tests set the environment variable `GENERATE_SNAPSHOTS=1`.

    GENERATE_SNAPSHOTS=1 riot run --pass-env -p3.12 test -k test_trace_missing_received


### Linting and formatting

To lint, format and type-check the code:

    riot run -s flake8
    riot run -s fmt
    riot run -s mypy

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

```bash
riot run reno new <short-description-of-change>
```

document the changes in the generated file, remove the irrelevant sections and
commit the release note with the change.


### Releasing

1. Checkout the `master` branch and make sure it's up to date.
```bash
    git checkout master && git pull
```
2. Generate the release notes and use [`pandoc`](https://pandoc.org/) to format
them for Github:
```bash
    riot run -s reno report --no-show-source | pandoc -f rst -t gfm --wrap=none
```
   Copy the output into a new release: https://github.com/DataDog/dd-apm-test-agent/releases/new.

2. Enter a tag for the release (following [`semver`](https://semver.org)) (eg. `v1.1.3`, `v1.0.3`, `v1.2.0`).
3. Use the tag without the `v` as the title.
4. Save the release as a draft and pass the link to someone else to give a quick review.
5. If all looks good hit publish
