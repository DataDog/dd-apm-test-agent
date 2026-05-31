from unittest import mock

import pytest

from lapdog import cli


def test_mcp_command_registered():
    assert "mcp" in cli.LAPDOG_COMMANDS
    assert "mcp" in cli.LAPDOG_USAGE


def test_cmd_mcp_runs_server():
    # cmd_mcp does `from lapdog import mcp_server`, which binds the attribute on
    # the lapdog package, so patch it there.
    fake_module = mock.Mock()
    with mock.patch("lapdog.mcp_server", fake_module, create=True):
        cli.cmd_mcp()
    fake_module.run.assert_called_once_with()


def test_cmd_mcp_missing_dependency(capsys):
    real_import = __import__

    def fake_import(name, globals=None, locals=None, fromlist=(), level=0):
        if name == "lapdog" and fromlist and "mcp_server" in fromlist:
            raise ImportError("No module named 'mcp'")
        if name == "lapdog.mcp_server":
            raise ImportError("No module named 'mcp'")
        return real_import(name, globals, locals, fromlist, level)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        with pytest.raises(SystemExit) as exc:
            cli.cmd_mcp()
    assert exc.value.code == 1
    err = capsys.readouterr().err
    assert "ddapm-test-agent[mcp]" in err


# ---------------------------------------------------------------------------
# mcp_server tool tests — only when the optional mcp dep is installed.
# ---------------------------------------------------------------------------

pytest.importorskip("mcp")

from lapdog import mcp_server  # noqa: E402


def _event(custom):
    return {"event": {"custom": custom}}


def _list_response(spans):
    return {"result": {"events": [_event(s) for s in spans]}}


def _mock_post(spans):
    resp = mock.Mock()
    resp.json.return_value = _list_response(spans)
    resp.raise_for_status.return_value = None
    return mock.patch("lapdog.mcp_server.requests.post", return_value=resp)


def test_agent_base_url_from_pid_file():
    with mock.patch("lapdog.mcp_server._read_pid_file", return_value=(123, 9999)):
        assert mcp_server._agent_base_url() == "http://127.0.0.1:9999"


def test_agent_base_url_fallback(monkeypatch):
    monkeypatch.delenv("PORT", raising=False)
    with mock.patch("lapdog.mcp_server._read_pid_file", return_value=(None, None)):
        assert mcp_server._agent_base_url() == "http://127.0.0.1:8126"


def test_agent_base_url_env_fallback(monkeypatch):
    monkeypatch.setenv("PORT", "7000")
    with mock.patch("lapdog.mcp_server._read_pid_file", return_value=(None, None)):
        assert mcp_server._agent_base_url() == "http://127.0.0.1:7000"


def test_list_sessions_groups_and_rolls_up():
    spans = [
        {
            "session_id": "s1",
            "ml_app": "app-a",
            "status": "ok",
            "start_ns": 200,
            "duration": 50,
            "metrics": {"total_tokens": 10, "estimated_total_cost": 0.01},
        },
        {
            "session_id": "s1",
            "ml_app": "app-a",
            "status": "error",
            "start_ns": 100,
            "duration": 50,
            "metrics": {"total_tokens": 5, "estimated_total_cost": 0.02},
        },
        {
            "session_id": "s2",
            "ml_app": "app-b",
            "status": "ok",
            "start_ns": 300,
            "duration": 10,
            "metrics": {"total_tokens": 7, "estimated_total_cost": 0.03},
        },
    ]
    with _mock_post(spans):
        result = mcp_server.list_sessions()

    assert result["session_count"] == 2
    by_id = {s["session_id"]: s for s in result["sessions"]}
    s1 = by_id["s1"]
    assert s1["span_count"] == 2
    assert s1["error_count"] == 1
    assert s1["total_tokens"] == 15
    assert s1["estimated_total_cost"] == pytest.approx(0.03)
    assert s1["start_ns"] == 100
    assert s1["end_ns"] == 250
    assert by_id["s2"]["span_count"] == 1


def test_search_spans_forwards_query_and_trims():
    spans = [
        {
            "span_id": "a",
            "trace_id": "t",
            "session_id": "s1",
            "name": "llm.call",
            "ml_app": "app-a",
            "status": "error",
            "duration": 5,
            "start_ns": 1,
            "metrics": {"total_tokens": 3},
            "meta": {"input": "x" * 1000, "output": "ok"},
        }
    ]
    with _mock_post(spans) as post:
        result = mcp_server.search_spans("@status:error", limit=10)

    # query + limit are forwarded to the agent verbatim
    _, kwargs = post.call_args
    assert kwargs["json"] == {"list": {"limit": 10, "search": {"query": "@status:error"}}}

    assert result["span_count"] == 1
    span = result["spans"][0]
    assert span["span_id"] == "a"
    assert span["status"] == "error"
    # long input is truncated
    assert span["input"].endswith("…")
    assert len(span["input"]) == 501


def test_get_session_builds_tree():
    spans = [
        {"span_id": "root", "parent_id": "undefined", "session_id": "s1", "start_ns": 10, "name": "root"},
        {"span_id": "child1", "parent_id": "root", "session_id": "s1", "start_ns": 30, "name": "c1"},
        {"span_id": "child2", "parent_id": "root", "session_id": "s1", "start_ns": 20, "name": "c2"},
        {"span_id": "grandchild", "parent_id": "child1", "session_id": "s1", "start_ns": 40, "name": "gc"},
    ]
    with _mock_post(spans):
        result = mcp_server.get_session("s1")

    assert result["span_count"] == 4
    assert len(result["roots"]) == 1
    root = result["roots"][0]
    assert root["span_id"] == "root"
    # siblings sorted ascending by start_ns
    assert [c["name"] for c in root["children"]] == ["c2", "c1"]
    c1 = next(c for c in root["children"] if c["span_id"] == "child1")
    assert [g["span_id"] for g in c1["children"]] == ["grandchild"]


def test_post_list_raises_agent_unavailable():
    import requests

    with mock.patch("lapdog.mcp_server.requests.post", side_effect=requests.ConnectionError("boom")):
        with pytest.raises(mcp_server.AgentUnavailable) as exc:
            mcp_server._post_list("", 10)
    assert "lapdog start" in str(exc.value)
