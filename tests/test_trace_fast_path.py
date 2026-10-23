"""The trace fast path must be indistinguishable from the Python code path.

Every test compares against the Python implementation itself: json.dumps for scalars,
decode_v04 + pprint_trace + json.dumps for payloads, and an app with the fast path disabled
for HTTP responses and log records.
"""

from collections import OrderedDict
import json
import logging
import math
import os
import random
import struct
from typing import Any
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import cast

import msgpack
import pytest

from ddapm_test_agent import trace_fast_path
from ddapm_test_agent.agent import _parse_csv
from ddapm_test_agent.agent import make_app
from ddapm_test_agent.llmobs_trace import extract_llmobs_envelopes_from_v04_traces
from ddapm_test_agent.trace import decode_v04
from ddapm_test_agent.trace import pprint_trace
from ddapm_test_agent.trace_snapshot import DEFAULT_SNAPSHOT_IGNORES


MP = "application/msgpack"
REQUIRE_NATIVE = os.environ.get("DDAPM_TEST_AGENT_REQUIRE_NATIVE", "").lower() in ("1", "true", "yes")
requires_native = pytest.mark.skipif(
    not trace_fast_path.NATIVE_AVAILABLE and not REQUIRE_NATIVE, reason="native extension is not built"
)


def test_native_extension_available_when_required():
    if REQUIRE_NATIVE:
        assert trace_fast_path.NATIVE_AVAILABLE, "DDAPM_TEST_AGENT_REQUIRE_NATIVE is set but _native did not build"


# ---- payload generation ----------------------------------------------------------------------
class Dup:
    """A msgpack map with explicit key order, possibly with repeated keys."""

    def __init__(self, items: List[Tuple[Any, Any]]) -> None:
        self.items = items


def pack(obj: Any, single_float: bool = False) -> bytes:
    if isinstance(obj, Dup):
        n = len(obj.items)
        head = bytes([0x80 | n]) if n < 16 else b"\xde" + struct.pack(">H", n)
        return head + b"".join(pack(k, single_float) + pack(v, single_float) for k, v in obj.items)
    if isinstance(obj, list) and any(isinstance(x, (Dup, list, dict)) for x in obj):
        n = len(obj)
        head = bytes([0x90 | n]) if n < 16 else b"\xdc" + struct.pack(">H", n)
        return head + b"".join(pack(x, single_float) for x in obj)
    if isinstance(obj, dict) and any(isinstance(v, (Dup, list, dict)) for v in obj.values()):
        return pack(Dup(list(obj.items())), single_float)
    return cast(bytes, msgpack.packb(obj, use_single_float=single_float))


def bits_to_float(bits: int) -> float:
    return float(struct.unpack("<d", (bits & (2**64 - 1)).to_bytes(8, "little"))[0])


def float_to_bits(x: float) -> int:
    return int.from_bytes(struct.pack("<d", x), "little")


def rand_text(r: random.Random, maxlen: int = 12) -> str:
    out = []
    for _ in range(r.randrange(maxlen)):
        p = r.random()
        if p < 0.5:
            out.append(chr(r.randrange(0x20, 0x7F)))
        elif p < 0.65:
            out.append(chr(r.randrange(0, 0x20)) if r.random() < 0.8 else r.choice('"\\\x7f'))
        elif p < 0.8:
            out.append(chr(r.randrange(0x80, 0x800)))
        elif p < 0.92:
            cp = r.randrange(0x800, 0x10000)
            out.append("x" if 0xD800 <= cp <= 0xDFFF else chr(cp))
        else:
            out.append(chr(r.randrange(0x10000, 0x110000)))
    return "".join(out)


def rand_float(r: random.Random) -> float:
    p = r.random()
    if p < 0.4:
        return float(r.randrange(-5, 1000))
    if p < 0.7:
        return float(r.random() * 10 ** r.randrange(-8, 20))
    if p < 0.8:
        return float(r.choice([math.nan, math.inf, -math.inf, -0.0, 0.5, 0.25, 1e16, 1e15 + 0.5]))
    return bits_to_float(r.getrandbits(64))


def rand_value(r: random.Random, depth: int = 0) -> Any:
    p = r.random()
    if depth > 3 or p < 0.6:
        return r.choice(
            [
                lambda: None,
                lambda: r.random() < 0.5,
                lambda: r.randrange(-(2**63), 2**64),
                lambda: r.randrange(-40, 300),
                lambda: rand_float(r),
                lambda: rand_text(r),
            ]
        )()
    if p < 0.8:
        return [rand_value(r, depth + 1) for _ in range(r.randrange(4))]
    return {rand_text(r, 6): rand_value(r, depth + 1) for _ in range(r.randrange(4))}


def rand_span(r: random.Random, trace_ids: List[int], used_ids: List[Any], weird: bool) -> Any:
    sid: Any = r.getrandbits(63) or 1
    if weird and r.random() < 0.05 and used_ids:
        sid = r.choice(used_ids)
    if weird and r.random() < 0.02:
        sid = r.choice([0, False, True])
    used_ids.append(sid)
    s: Dict[str, Any] = {"trace_id": r.choice(trace_ids), "span_id": sid, "name": rand_text(r, 8) or "n"}
    if r.random() < 0.8:
        s["parent_id"] = r.choice([0, None, r.choice(used_ids), r.getrandbits(63)])
    for k in ("resource", "service", "type"):
        if r.random() < 0.7:
            s[k] = rand_text(r, 10) if r.random() < 0.9 else None
    if r.random() < 0.9:
        s["start"] = r.getrandbits(62) if r.random() < 0.95 else rand_float(r)
    if r.random() < 0.9:
        s["duration"] = r.getrandbits(40)
    if r.random() < 0.8:
        s["error"] = r.choice([0, 1, True])
    if r.random() < 0.8:
        s["meta"] = {rand_text(r, 8): rand_text(r, 16) for _ in range(r.randrange(12))}
    if r.random() < 0.8:
        s["metrics"] = {
            rand_text(r, 8): (rand_float(r) if r.random() < 0.7 else r.randrange(-10, 10**12))
            for _ in range(r.randrange(12))
        }
    if r.random() < 0.1:
        s["meta_struct"] = {
            rand_text(r, 5): msgpack.packb({rand_text(r, 4): rand_value(r) for _ in range(r.randrange(4))})
            for _ in range(r.randrange(1, 3))
        }
    if r.random() < 0.2:
        s[rand_text(r, 6) or "extra"] = rand_value(r)
    if weird:
        p = r.random()
        if p < 0.02:
            s["name"] = r.randrange(5)
        elif p < 0.04:
            s.setdefault("meta", {})["bad"] = r.randrange(5)
        elif p < 0.06:
            s.setdefault("metrics", {})["bad"] = "x"
        elif p < 0.08:
            s["start"] = r.choice(["x", None, [1]])
        elif p < 0.10:
            s["blob"] = b"\x00\x01"
        elif p < 0.12:
            s["ext"] = msgpack.ExtType(3, b"z")
        elif p < 0.13:
            s["span_links"] = [{"trace_id": 1, "span_id": 2}]
        elif p < 0.14:
            s["meta_struct"] = {"_llmobs": msgpack.packb({"span_id": "1", "trace_id": "2"})}
        elif p < 0.15:
            del s[r.choice(["trace_id", "span_id", "name"])]
        elif p < 0.17:
            items = list(s.items())
            items.insert(r.randrange(len(items) + 1), r.choice(items))
            return Dup(items)
        elif p < 0.19 and s.get("meta"):
            k = next(iter(s["meta"]))
            s["meta"] = Dup(list(s["meta"].items()) + [(k, "dup")])
    return s


def rand_payload(r: random.Random, weird: bool) -> bytes:
    trace_ids = [r.getrandbits(64) for _ in range(r.randrange(1, 4))] + ([-3] if r.random() < 0.05 else [])
    chunks = []
    for _ in range(r.randrange(1, 4)):
        used: List[Any] = []
        chunks.append([rand_span(r, trace_ids, used, weird) for _ in range(r.randrange(0, 12))])
    if r.random() < 0.2:
        try:
            return pack(chunks, single_float=True)
        except OverflowError:
            pass
    return pack(chunks)


def mutate(r: random.Random, data: bytes) -> bytes:
    b = bytearray(data)
    for _ in range(r.randrange(1, 4)):
        p = r.random()
        if p < 0.5 and b:
            b[r.randrange(len(b))] = r.getrandbits(8)
        elif p < 0.7 and b:
            del b[r.randrange(len(b)) :]
        elif p < 0.85:
            b.insert(r.randrange(len(b) + 1), r.getrandbits(8))
        else:
            b += bytes(r.getrandbits(8) for _ in range(r.randrange(1, 4)))
    return bytes(b)


def span(**kw: Any) -> Dict[str, Any]:
    s: Dict[str, Any] = {"trace_id": 1, "span_id": 2, "parent_id": 0, "name": "n", "start": 1, "duration": 2}
    s.update(kw)
    return s


def may_hang_python_path(data: bytes) -> bool:
    """pprint_trace can loop forever on a chunk with a 0 or repeated span_id."""
    try:
        traces = decode_v04(MP, data, False)
    except Exception:
        return False
    for trace in traces:
        ids = [s["span_id"] for s in trace]
        if any(i == 0 for i in ids) or len(set(ids)) != len(ids):
            return True
    return False


# ---- oracle -----------------------------------------------------------------------------------
def python_session_body(payloads: List[bytes]) -> bytes:
    tracemap: Dict[Any, List[Any]] = OrderedDict()
    for data in payloads:
        for trace in decode_v04(MP, data, False):
            for s in trace:
                tracemap.setdefault(s["trace_id"], []).append(s)
    return json.dumps(list(tracemap.values())).encode()


def assert_python_path_silent(data: bytes) -> None:
    """Run what Agent._handle_traces does for v0.4 with no checks and logging above INFO."""
    traces = decode_v04(MP, data, False)
    for trace in traces:
        try:
            pprint_trace(trace, trace_fast_path.NATIVE_LOG_SPAN_FMT)
        except ValueError:
            pass
    assert extract_llmobs_envelopes_from_v04_traces(traces) == []


def native_fragments(data: bytes) -> Optional[trace_fast_path.Fragments]:
    return trace_fast_path._transcode_v04(data)


def check_payload(data: bytes) -> bool:
    frags = native_fragments(data)
    if frags is None:
        return False
    assert_python_path_silent(data)
    assert trace_fast_path.session_traces_body([frags]) == python_session_body([data]), data
    return True


# ---- scalars ----------------------------------------------------------------------------------
@requires_native
def test_format_double_matches_json_dumps():
    assert trace_fast_path._native is not None
    r = random.Random(0)
    cases = [0.0, -0.0, math.nan, math.inf, -math.inf]
    for e in range(-1074, 1024):
        x = math.ldexp(1.0, e)
        cases += [x, -x, bits_to_float(float_to_bits(x) + 1), bits_to_float(float_to_bits(x) - 1)]
    for base in (1e15, 1e16, 2.0**53, 1e17, 1e-4, 1e-5, 0.1, 1e22, 5e-324, 2.2250738585072014e-308):
        bits = float_to_bits(base)
        for i in range(-20, 20):
            x = bits_to_float(bits + i)
            cases += [x, -x]
    for _ in range(50_000):
        cases.append(bits_to_float(r.getrandbits(64)))
        cases.append(struct.unpack("<f", r.getrandbits(32).to_bytes(4, "little"))[0])
        cases.append(float("%de%d" % (r.randrange(10 ** r.randrange(1, 18)), r.randrange(-30, 30))))
    mismatches = [(x, trace_fast_path._native.format_double(x), json.dumps(x)) for x in cases]
    mismatches = [m for m in mismatches if m[1] != m[2]]
    assert not mismatches, mismatches[:10]


@requires_native
def test_format_str_matches_json_dumps():
    assert trace_fast_path._native is not None
    r = random.Random(0)
    for _ in range(20_000):
        s = rand_text(r, 40)
        assert trace_fast_path._native.format_str(s.encode()) == json.dumps(s), s
        raw = bytes(r.getrandbits(8) for _ in range(r.randrange(12)))
        try:
            expected: Optional[str] = json.dumps(raw.decode("utf-8"))
        except UnicodeDecodeError:
            expected = None
        assert trace_fast_path._native.format_str(raw) == expected, raw
    invalid = [chr(cp).encode("utf-8", "surrogatepass") for cp in (0xD800, 0xDBFF, 0xDC00, 0xDFFF)]
    invalid += [b"\xc0\x80", b"\xe0\x80\x80", b"\xf0\x80\x80\x80", b"\xf4\x90\x80\x80", b"\xc3", b"\xe2\x82"]
    for raw in invalid:
        assert trace_fast_path._native.format_str(raw) is None, raw


# ---- payloads ---------------------------------------------------------------------------------
@requires_native
@pytest.mark.parametrize("seed", [0, 1, 2])
def test_transcode_v04_matches_python_path(seed):
    r = random.Random(seed)
    corpus = [rand_payload(r, weird=i % 2 == 1) for i in range(1500)]
    native = sum(check_payload(data) for data in corpus)
    # Valid payloads always take the native path.
    assert native >= 750
    for _ in range(1500):
        check_payload(mutate(r, r.choice(corpus)))
    for _ in range(300):
        group = [r.choice(corpus) for _ in range(r.randrange(1, 6))]
        frags = [native_fragments(data) for data in group]
        if all(f is not None for f in frags):
            assert trace_fast_path.session_traces_body([f for f in frags if f is not None]) == python_session_body(
                group
            )


@requires_native
@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(
            pack([[Dup([("trace_id", 1), ("span_id", 2), ("name", "a"), ("name", "b")])]]), id="duplicate-span-key"
        ),
        pytest.param(pack([[span(meta=Dup([("k", "a"), ("k", "b")]))]]), id="duplicate-meta-key"),
        pytest.param(msgpack.packb([[span(start="x"), span(span_id=3, parent_id=2, start=1)]]), id="non-numeric-start"),
        pytest.param(msgpack.packb([[span(span_id=0)]]), id="zero-span-id"),
        pytest.param(msgpack.packb([[span(), span(parent_id=2)]]), id="repeated-span-id"),
        pytest.param(msgpack.packb([[span(meta_struct={"_llmobs": msgpack.packb({"a": 1})})]]), id="llmobs"),
        pytest.param(msgpack.packb([[span(x=msgpack.ExtType(1, b"x"))]]), id="ext-type"),
        pytest.param(msgpack.packb([[span(x=b"bytes")]]), id="bytes-value"),
        pytest.param(msgpack.packb([[span()]]) + b"\x00", id="trailing-bytes"),
        pytest.param(msgpack.packb([[span(name="n")]]).replace(b"\xa1n", b"\xa1\xff"), id="invalid-utf8"),
        pytest.param(msgpack.packb([[span(span_links=[{"trace_id": 1, "span_id": 2}])]]), id="span-links"),
        pytest.param(msgpack.packb([[span(span_events=[{"name": "e", "time_unix_nano": 1}])]]), id="span-events"),
        pytest.param(msgpack.packb([[{"trace_id": 1, "span_id": 2}]]), id="missing-name"),
        pytest.param(msgpack.packb([[span(meta={"k": 1})]]), id="non-str-meta"),
        pytest.param(msgpack.packb({"not": "a list"}), id="not-a-list"),
    ],
)
def test_transcode_v04_defers_to_python_path(payload):
    assert native_fragments(payload) is None


@requires_native
def test_transcode_v04_handles_reference_payload(v04_reference_http_trace_payload_data_raw):
    # Span links and events are left to the Python path.
    for trace in v04_reference_http_trace_payload_data_raw:
        for s in trace:
            s.pop("span_events", None)
    assert check_payload(msgpack.packb(v04_reference_http_trace_payload_data_raw))


# ---- HTTP -------------------------------------------------------------------------------------
class _Records(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append("%s %s" % (record.levelname, record.getMessage()))


@pytest.fixture
def agent_log_above_info():
    logger = logging.getLogger("ddapm_test_agent.agent")
    level = logger.level
    logger.setLevel(logging.WARNING)
    records = _Records()
    logger.addHandler(records)
    yield records
    logger.removeHandler(records)
    logger.setLevel(level)


def _app(tmp_path: Any, fast_path: bool) -> Any:
    return make_app(
        enabled_checks=[],
        log_span_fmt="[{name}]",
        snapshot_dir=str(tmp_path),
        snapshot_ci_mode=False,
        snapshot_ignored_attrs=_parse_csv(DEFAULT_SNAPSHOT_IGNORES),
        agent_url="",
        trace_request_delay=0.0,
        suppress_trace_parse_errors=False,
        pool_trace_check_failures=True,
        disable_error_responses=False,
        snapshot_removed_attrs=[],
        snapshot_regex_placeholders={},
        vcr_cassettes_directory=str(tmp_path),
        vcr_ci_mode=False,
        vcr_provider_map="",
        vcr_ignore_headers="",
        vcr_json_body_normalizers="",
        vcr_body_regex_normalizers="",
        dd_site="datadoghq.com",
        dd_api_key="1234567890",
        disable_llmobs_data_forwarding=True,
        trace_fast_path=fast_path,
    )


def _v05_payload(r: random.Random) -> bytes:
    strings = ["", "svc", "op", "res", "gpu", "k", "v", "m"]
    v05_span = [1, 2, 3, r.getrandbits(63), r.getrandbits(63), 0, 10, 20, 0, {5: 6}, {7: 1.5}, 4]
    return cast(bytes, msgpack.packb([strings, [[v05_span]]]))


@requires_native
async def test_http_responses_and_logs_identical(aiohttp_client, tmp_path, agent_log_above_info, monkeypatch):
    native_hits = []
    transcode = trace_fast_path._transcode_v04

    def counting_transcode(data: bytes) -> Optional[trace_fast_path.Fragments]:
        res: Optional[trace_fast_path.Fragments] = transcode(data)
        native_hits.append(res is not None)
        return res

    monkeypatch.setattr(trace_fast_path, "_transcode_v04", counting_transcode)
    fast = await aiohttp_client(_app(tmp_path / "fast", True))
    slow = await aiohttp_client(_app(tmp_path / "slow", False))
    ports = [str(fast.port), str(slow.port)]

    async def both(method: str, path: str, **kwargs: Any) -> Tuple[int, Optional[str], Optional[str], bytes]:
        out = []
        for client, port in ((fast, ports[0]), (slow, ports[1])):
            before = len(agent_log_above_info.messages)
            resp = await client.request(method, path, **kwargs)
            body = (await resp.read()).replace(port.encode(), b"PORT")
            logs = [m.replace(port, "PORT") for m in agent_log_above_info.messages[before:]]
            out.append((resp.status, resp.reason, resp.headers.get("Content-Type"), body, logs))
        assert out[0] == out[1], (method, path, kwargs.get("data", b"")[:200])
        return out[0][:4]

    r = random.Random(3)
    corpus = [rand_payload(r, weird=i % 2 == 1) for i in range(400)]
    corpus += [mutate(r, r.choice(corpus)) for _ in range(300)]
    corpus = [data for data in corpus if not may_hang_python_path(data)]
    corpus += [
        msgpack.packb([[span(span_id=1), span(span_id=5, parent_id=1), span(span_id=5, parent_id=1)]]),
        msgpack.packb([[span(start="x"), span(span_id=3, parent_id=2, start=1)]]),
        msgpack.packb([[span(meta_struct={"_llmobs": msgpack.packb({"span_id": "1", "trace_id": "2"})})]]),
        msgpack.packb([[span()]]) + b"\x00",
    ]
    r.shuffle(corpus)
    tokens = [None, "t1", "t2", "t3"]
    for i, data in enumerate(corpus):
        token = r.choice(tokens)
        headers = {"Content-Type": MP, "X-Datadog-Trace-Count": "1"}
        if token:
            headers["X-Datadog-Test-Session-Token"] = token
        await both(r.choice(["PUT", "POST"]), "/v0.4/traces", data=data, headers=headers)
        if r.random() < 0.02:
            json_headers = {k: v for k, v in headers.items() if k != "Content-Type"}
            json_body = json.dumps([[{"trace_id": 5, "span_id": 6, "name": "j"}]])
            await both(
                "PUT", "/v0.4/traces", data=json_body, headers={"Content-Type": "application/json", **json_headers}
            )
        if r.random() < 0.02:
            await both("PUT", "/v0.5/traces", data=_v05_payload(r), headers=headers)
        if i == len(corpus) // 3:
            await both("GET", "/test/session/start?test_session_token=t3")
        if i == 2 * len(corpus) // 3:
            await both("GET", "/test/session/clear?test_session_token=t2")
        if r.random() < 0.05 or i == len(corpus) - 1:
            for t in tokens:
                q = "?test_session_token=%s" % t if t else ""
                await both("GET", "/test/session/traces" + q)
                await both("GET", "/test/session/requests" + q)
                await both("GET", "/test/trace_check/failures" + (q + "&" if q else "?") + "use_json=true")
                await both("GET", "/test/trace_check/summary" + q)
    assert sum(native_hits) > 200, "the native path was not used"


@requires_native
async def test_info_logging_uses_python_path(
    aiohttp_client, tmp_path, monkeypatch, v04_reference_http_trace_payload_data
):
    calls = []
    monkeypatch.setattr(trace_fast_path, "transcode_v04", lambda data: calls.append(data))
    logging.getLogger("ddapm_test_agent.agent").setLevel(logging.INFO)
    try:
        client = await aiohttp_client(_app(tmp_path, True))
        resp = await client.put(
            "/v0.4/traces", data=v04_reference_http_trace_payload_data, headers={"Content-Type": MP}
        )
        assert resp.status == 200, await resp.text()
    finally:
        logging.getLogger("ddapm_test_agent.agent").setLevel(logging.NOTSET)
    assert calls == [], "span trees are logged at INFO, so the payload must be decoded in Python"
