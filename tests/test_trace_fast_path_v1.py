"""The native v1 fast path must be indistinguishable from trace.decode_v1 and the Python path."""

from collections import OrderedDict
import json
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
from ddapm_test_agent.trace import decode_v1
from ddapm_test_agent.trace import pprint_trace

from .test_trace_fast_path import MP
from .test_trace_fast_path import _app
from .test_trace_fast_path import mutate
from .test_trace_fast_path import rand_float
from .test_trace_fast_path import rand_text
from .test_trace_fast_path import requires_native


# ---- v1 encoding --------------------------------------------------------------------------------
class S:
    """A string resolved at pack time: inline the first time (or randomly again), else by index."""

    def __init__(self, text: str) -> None:
        self.text = text


class Raw:
    """Bytes spliced into the payload as-is (to build invalid payloads)."""

    def __init__(self, data: bytes) -> None:
        self.data = data


class Map:
    """A msgpack map with explicit key order, possibly with repeated keys."""

    def __init__(self, items: List[Tuple[Any, Any]]) -> None:
        self.items = items


class Packer:
    def __init__(self, r: random.Random) -> None:
        self.r = r
        self.table: Dict[str, int] = {"": 0}
        self.size = 1

    def pack(self, obj: Any) -> bytes:
        if isinstance(obj, S):
            idx = self.table.get(obj.text)
            if idx is not None and self.r.random() < 0.8:
                return cast(bytes, msgpack.packb(idx))
            self.table.setdefault(obj.text, self.size)
            self.size += 1
            return cast(bytes, msgpack.packb(obj.text))
        if isinstance(obj, Raw):
            return obj.data
        if isinstance(obj, Map):
            n = len(obj.items)
            head = bytes([0x80 | n]) if n < 16 else b"\xde" + struct.pack(">H", n)
            return head + b"".join(self.pack(k) + self.pack(v) for k, v in obj.items)
        if isinstance(obj, list):
            n = len(obj)
            head = bytes([0x90 | n]) if n < 16 else b"\xdc" + struct.pack(">H", n)
            return head + b"".join(self.pack(x) for x in obj)
        return cast(bytes, msgpack.packb(obj))


STRING, BOOL, DOUBLE, INT, BYTES, ARRAY = 1, 2, 3, 4, 5, 6


def rand_attrs(r: random.Random, keys: List[str], weird: bool) -> List[Any]:
    out: List[Any] = []
    for _ in range(r.randrange(8)):
        key = r.choice(keys) if keys and r.random() < 0.3 else (rand_text(r, 8) or "k")
        keys.append(key)
        p = r.random()
        if p < 0.45:
            out += [S(key), STRING, S(rand_text(r, 12))]
        elif p < 0.6:
            out += [S(key), BOOL, r.random() < 0.5]
        elif p < 0.8:
            out += [S(key), DOUBLE, rand_float(r)]
        else:
            out += [S(key), INT, r.randrange(-(2**63), 2**64)]
    if weird and r.random() < 0.2:
        out += r.choice(
            [
                [S("b"), BYTES, b"x"],
                [S("a"), ARRAY, [STRING, S("x")]],
                [S("t"), 9, 1],
                [S("s"), STRING, 10**6],
                [S("x"), DOUBLE, "str"],
                [S("x"), BOOL, 1],
                [S("dangling")],
            ]
        )
    return out


def rand_span(r: random.Random, ids: List[int], keys: List[str], weird: bool) -> Any:
    sid = r.getrandbits(63) or 1
    ids.append(sid)
    items: List[Tuple[Any, Any]] = [(4, sid), (2, S(r.choice(["gpu.kernel", "op", rand_text(r, 6) or "n"])))]
    if r.random() < 0.9:
        items.append((1, S(r.choice(["svc", rand_text(r, 6)]))))
    if r.random() < 0.8:
        items.append((3, S(rand_text(r, 10))))
    if r.random() < 0.8:
        items.append((5, r.choice([0, r.choice(ids), r.getrandbits(63)])))
    if r.random() < 0.9:
        items.append((6, r.getrandbits(62) if r.random() < 0.95 else rand_float(r)))
    if r.random() < 0.9:
        items.append((7, r.getrandbits(40)))
    if r.random() < 0.8:
        items.append((8, r.random() < 0.2))
    if r.random() < 0.8:
        items.append((9, rand_attrs(r, keys, weird)))
    if r.random() < 0.6:
        items.append((10, S(r.choice(["gpu", "web", ""]))))
    for key in (13, 14, 15):
        if r.random() < 0.3:
            items.append((key, S(r.choice(["", "prod", "1.2.3", rand_text(r, 5)]))))
    if r.random() < 0.3:
        items.append((16, r.randrange(6)))
    if r.random() < 0.1:
        items.append((r.choice([20, -1, "x", None]), rand_text(r, 4)))
    if weird:
        p = r.random()
        if p < 0.03:
            items.append((8, 1))
        elif p < 0.06:
            items = [kv for kv in items if kv[0] != r.choice([2, 4])]
        elif p < 0.09:
            items.append((6, "x"))
        elif p < 0.11:
            items.append((16, 9))
        elif p < 0.13:
            items.append((11, []))
        elif p < 0.15:
            items.append(r.choice(items))  # repeated key
        elif p < 0.17:
            items.append((True, S("bool key")))
        elif p < 0.19:
            items[0] = (4, r.choice([0, ids[0]]))
        elif p < 0.21:
            items.append((2, 10**6))  # dangling string index
    r.shuffle(items)
    return Map(items)


def rand_chunk(r: random.Random, keys: List[str], weird: bool) -> Any:
    ids: List[int] = []
    items: List[Tuple[Any, Any]] = [(4, [rand_span(r, ids, keys, weird) for _ in range(r.randrange(0, 10))])]
    hi = r.choice([0, r.getrandbits(64)])
    if r.random() < 0.9:
        items.append((6, hi.to_bytes(8, "big") + r.getrandbits(64).to_bytes(8, "big")))
    if r.random() < 0.6:
        items.append((1, r.choice([0, 1, 2, -1])))
    if r.random() < 0.4:
        items.append((2, S(r.choice(["", "synthetics", "rum"]))))
    if r.random() < 0.5:
        items.append((3, rand_attrs(r, keys, weird)))
    if r.random() < 0.4:
        items.append((7, r.choice([0, 4, 8, -3])))
    if weird:
        p = r.random()
        if p < 0.03:
            items.append((5, True))
        elif p < 0.06:
            items.append((6, b"short"))
        elif p < 0.08:
            items.append((99, 1))
        elif p < 0.10:
            items.append(r.choice(items))
    r.shuffle(items)
    return Map(items)


def rand_payload(r: random.Random, weird: bool) -> bytes:
    keys: List[str] = []
    items: List[Tuple[Any, Any]] = [(11, [rand_chunk(r, keys, weird) for _ in range(r.randrange(1, 4))])]
    for key in r.sample(range(2, 10), r.randrange(4)):
        items.append((key, S(r.choice(["python", "3.12", rand_text(r, 6)])) if r.random() < 0.8 else r.randrange(5)))
    if r.random() < 0.5:
        items.append((10, rand_attrs(r, keys, weird)))
    if weird and r.random() < 0.05:
        items.append((1, []))
    r.shuffle(items)
    data = Packer(r).pack(Map(items))
    if weird and r.random() < 0.03:
        data += b"\x00"
    return data


# ---- oracle -------------------------------------------------------------------------------------
def python_session_body(payloads: List[bytes]) -> bytes:
    tracemap: Dict[Any, List[Any]] = OrderedDict()
    for data in payloads:
        for trace in decode_v1(data):
            for s in trace:
                tracemap.setdefault(s["trace_id"], []).append(s)
    return json.dumps(list(tracemap.values())).encode()


def assert_python_path_silent(data: bytes) -> None:
    for trace in decode_v1(data):
        try:
            pprint_trace(trace, trace_fast_path.NATIVE_LOG_SPAN_FMT)
        except ValueError:
            pass


def native_fragments(data: bytes) -> Optional[trace_fast_path.Fragments]:
    return trace_fast_path.transcode_v1(data)


def check_payload(data: bytes) -> bool:
    frags = native_fragments(data)
    if frags is None:
        return False
    assert_python_path_silent(data)
    assert trace_fast_path.session_traces_body([frags]) == python_session_body([data]), data
    return True


def may_hang_python_path(data: bytes) -> bool:
    try:
        traces = decode_v1(data)
    except Exception:
        return False
    for trace in traces:
        ids = [s.get("span_id") for s in trace]
        if any(i == 0 for i in ids) or len(set(map(repr, ids))) != len(ids):
            return True
    return False


# ---- tests --------------------------------------------------------------------------------------
@requires_native
@pytest.mark.parametrize("seed", [0, 1, 2])
def test_transcode_v1_matches_python_path(seed):
    r = random.Random(seed)
    corpus = [rand_payload(r, weird=i % 2 == 1) for i in range(1500)]
    native = sum(check_payload(data) for data in corpus)
    assert native >= 600
    for _ in range(1500):
        check_payload(mutate(r, r.choice(corpus)))
    for _ in range(300):
        group = [r.choice(corpus) for _ in range(r.randrange(1, 6))]
        frags = [native_fragments(data) for data in group]
        if all(f is not None for f in frags):
            assert trace_fast_path.session_traces_body([f for f in frags if f is not None]) == python_session_body(
                group
            )


def _v1(payload: Any) -> bytes:
    return Packer(random.Random(0)).pack(payload)


def _span(*extra: Tuple[Any, Any]) -> Map:
    return Map([(4, 7), (2, S("n")), (6, 1)] + list(extra))


def _chunk(*spans: Map) -> Map:
    return Map([(4, list(spans)), (6, bytes(16))])


@requires_native
@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(_v1(Map([(11, [_chunk(_span((9, [S("b"), BYTES, b"x"])))])])), id="bytes-attribute"),
        pytest.param(_v1(Map([(11, [_chunk(_span((9, [S("a"), ARRAY, [STRING, S("x")]])))])])), id="array-attribute"),
        pytest.param(_v1(Map([(11, [_chunk(_span((8, 1)))])])), id="non-bool-error"),
        pytest.param(_v1(Map([(11, [_chunk(Map([(4, 7), (6, 1)]))])])), id="missing-name"),
        pytest.param(_v1(Map([(11, [_chunk(Map([(2, S("n")), (6, 1)]))])])), id="missing-span-id"),
        pytest.param(_v1(Map([(11, [_chunk(_span((6, "x")))])])), id="non-numeric-start"),
        pytest.param(_v1(Map([(11, [_chunk(_span(), _span())])])), id="repeated-span-id"),
        pytest.param(_v1(Map([(11, [_chunk(_span((2, S("m"))))])])), id="repeated-span-key"),
        pytest.param(_v1(Map([(11, [_chunk(_span((11, [])))])])), id="span-links"),
        pytest.param(_v1(Map([(11, [_chunk(_span((2, 99)))])])), id="dangling-string-index"),
        pytest.param(_v1(Map([(11, [Map([(4, []), (5, True)])])])), id="dropped-trace"),
        pytest.param(_v1(Map([(1, []), (11, [])])), id="non-streamed-strings"),
        pytest.param(_v1(Map([(11, [_chunk(_span())])])) + b"\x00", id="trailing-bytes"),
        pytest.param(_v1([1, 2]), id="not-a-map"),
    ],
)
def test_transcode_v1_defers_to_python_path(payload):
    assert native_fragments(payload) is None


@requires_native
def test_transcode_v1_chunk_and_payload_fields():
    data = _v1(
        Map(
            [
                (2, S("python")),
                (
                    11,
                    [
                        Map(
                            [
                                (1, 2),
                                (2, S("synthetics")),
                                (3, [S("chunk"), INT, 5]),
                                (4, [_span((13, S("prod")), (16, 2)), Map([(4, 8), (2, S("n")), (6, 2)])]),
                                (6, (2**64 + 3).to_bytes(16, "big")),
                                (7, 4),
                            ]
                        )
                    ],
                ),
                (10, [S("_dd.apm_mode"), STRING, S("edge"), S("env"), STRING, S("ignored")]),
            ]
        )
    )
    assert check_payload(data)


@requires_native
async def test_http_v1_responses_and_logs_identical(aiohttp_client, tmp_path, agent_log_above_info, monkeypatch):
    native_hits = []
    transcode = trace_fast_path.transcode_v1

    def counting_transcode(data: bytes) -> Optional[trace_fast_path.Fragments]:
        res: Optional[trace_fast_path.Fragments] = transcode(data)
        native_hits.append(res is not None)
        return res

    monkeypatch.setattr(trace_fast_path, "transcode_v1", counting_transcode)
    fast = await aiohttp_client(_app(tmp_path / "fast", True))
    slow = await aiohttp_client(_app(tmp_path / "slow", False))

    async def both(method: str, path: str, **kwargs: Any) -> None:
        out = []
        for client in (fast, slow):
            before = len(agent_log_above_info.messages)
            resp = await client.request(method, path, **kwargs)
            body = await resp.read()
            logs = agent_log_above_info.messages[before:]
            headers = sorted((k, v) for k, v in resp.headers.items() if k != "Date")
            out.append((resp.status, resp.reason, headers, body, logs))
        assert out[0] == out[1], (method, path)

    r = random.Random(5)
    corpus = [rand_payload(r, weird=i % 2 == 1) for i in range(400)]
    corpus += [mutate(r, r.choice(corpus)) for _ in range(200)]
    corpus = [data for data in corpus if not may_hang_python_path(data)]
    for i, data in enumerate(corpus):
        token = r.choice([None, "t1", "t2"])
        headers = {"Content-Type": MP}
        if token:
            headers["X-Datadog-Test-Session-Token"] = token
        await both("PUT", "/v1.0/traces", data=data, headers=headers)
        if r.random() < 0.05 or i == len(corpus) - 1:
            for t in (None, "t1", "t2"):
                q = "?test_session_token=%s" % t if t else ""
                await both("GET", "/test/session/traces" + q)
                await both("GET", "/test/trace_check/failures" + (q + "&" if q else "?") + "use_json=true")
    assert sum(native_hits) > 100, "the native path was not used"
