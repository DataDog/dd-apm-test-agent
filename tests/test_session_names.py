import json

import pytest

from lapdog import backfill_codex
from lapdog.claude_hooks import ClaudeHooksAPI
from lapdog.claude_link_tracker import ClaudeLinkTracker
from lapdog.claude_proxy import ClaudeProxyAPI
from lapdog.claude_proxy import _is_session_naming_request
from lapdog.codex_hooks import CodexHooksAPI
from lapdog.codex_watcher import FileState
from lapdog.codex_watcher import SessionNames
from lapdog.codex_watcher import _drain_file


def _naming_request():
    return {
        "messages": [{"role": "user", "content": "<session>\nA task\n</session>"}],
        "output_config": {
            "format": {
                "type": "json_schema",
                "schema": {
                    "type": "object",
                    "properties": {"title": {"type": "string"}},
                    "required": ["title"],
                    "additionalProperties": False,
                },
            }
        },
    }


@pytest.mark.parametrize("legacy_format", [False, True])
def test_claude_naming_schema_does_not_depend_on_prompt_wording(legacy_format):
    request = _naming_request()
    request["system"] = "A different prompt in a future release"
    if legacy_format:
        request["output_format"] = request.pop("output_config")["format"]
    assert _is_session_naming_request(request)


@pytest.mark.parametrize("change", ["tools", "extra_message", "no_wrapper", "wrong_schema", "missing_required"])
def test_claude_naming_request_rejects_unrelated_calls(change):
    request = _naming_request()
    request["system"] = "You are naming a coding session"
    if change == "tools":
        request["tools"] = [{"name": "Bash"}]
    elif change == "extra_message":
        request["messages"].append({"role": "assistant", "content": "Earlier reply"})
    elif change == "no_wrapper":
        request["messages"][0]["content"] = "Return JSON with a title"
    elif change == "wrong_schema":
        request["output_config"]["format"]["schema"]["properties"]["branch"] = {"type": "string"}
    else:
        request["output_config"]["format"]["schema"].pop("required")
    assert not _is_session_naming_request(request)


def test_claude_prompt_text_alone_does_not_mark_naming_request():
    assert not _is_session_naming_request({"system": "You are naming a coding session"})


@pytest.mark.parametrize(
    "system,response",
    [
        ("You are naming a coding session so the user can pick it out", '{"title":"Session metadata"}'),
        ([{"type": "text", "text": "You are naming a coding session"}], '{"title":"Session metadata"}'),
        ("Legacy prompt", '{"title":"Session metadata","isNewTopic":true}'),
    ],
)
def test_claude_name_updates_existing_and_future_spans(system, response):
    hooks = ClaudeHooksAPI()
    proxy = ClaudeProxyAPI(hooks_api=hooks, link_tracker=ClaudeLinkTracker())
    session = hooks._get_or_create_session("claude")
    old = {"session_id": "claude", "meta": {"metadata": {"keep": True}}}
    other = {"session_id": "other"}
    hooks._append_span(old)
    hooks._append_span(other)
    request = {"system": system, "messages": [{"role": "user", "content": "<session>\nA task\n</session>"}]}
    proxy._extract_conversation_title(
        session, [{"type": "text", "text": response}], _is_session_naming_request(request)
    )
    new = {"session_id": "claude"}
    hooks._append_span(new)
    assert old["meta"]["metadata"] == {"keep": True, "session_name": "Session metadata"}
    assert new["meta"]["metadata"]["session_name"] == "Session metadata"
    assert "meta" not in other


@pytest.mark.parametrize("response", ['{"title":"Unrelated JSON"}', "[]", '{"title":null}', "not JSON"])
def test_claude_ordinary_responses_do_not_set_name(response):
    hooks = ClaudeHooksAPI()
    proxy = ClaudeProxyAPI(hooks_api=hooks, link_tracker=ClaudeLinkTracker())
    session = hooks._get_or_create_session("claude")
    proxy._extract_conversation_title(session, [{"type": "text", "text": response}], False)
    assert session.session_name == ""


@pytest.mark.parametrize(
    "response",
    ['{"title":"Name","extra":true}', '{"title":"Name","isNewTopic":"yes"}', '{"title":"  "}', '{"title":7}'],
)
def test_claude_naming_response_requires_valid_title_object(response):
    hooks = ClaudeHooksAPI()
    proxy = ClaudeProxyAPI(hooks_api=hooks, link_tracker=ClaudeLinkTracker())
    session = hooks._get_or_create_session("claude")
    proxy._extract_conversation_title(session, [{"type": "text", "text": response}], True)
    assert session.session_name == ""


def test_codex_grouped_names_and_rename_back():
    hooks = ClaudeHooksAPI()
    codex = CodexHooksAPI(hooks)

    def rename(session_id, name):
        codex._dispatch(session_id, {"type": "event_msg", "payload": {"type": "session_name", "name": name}})

    rename("parent", "Parent name")
    rename("child", "Child name")
    child_span = {"session_id": "child"}
    hooks._append_span(child_span)
    codex._set_session_group("child", "parent")
    rename("child", "Must not replace parent")
    assert child_span["meta"]["metadata"]["session_name"] == "Parent name"
    rename("parent", "New name")
    assert child_span["meta"]["metadata"]["session_name"] == "New name"
    rename("parent", "Parent name")
    future = {"session_id": "parent"}
    hooks._append_span(future)
    assert future["meta"]["metadata"]["session_name"] == "Parent name"
    assert child_span["meta"]["metadata"]["session_name"] == "Parent name"


def test_claude_title_span_before_session_is_adopted():
    hooks = ClaudeHooksAPI()
    proxy = ClaudeProxyAPI(hooks_api=hooks, link_tracker=ClaudeLinkTracker())
    title_span = proxy._create_llm_span(
        None,
        _naming_request(),
        {"content": [{"type": "text", "text": '{"title":"Early title"}'}], "usage": {}},
        1,
        1,
    )
    hooks._append_span(title_span)
    proxy._orphan_spans.append(title_span)
    session = hooks._get_or_create_session("claude")
    proxy._adopt_orphan_spans(session)
    assert title_span["session_id"] == "claude"
    assert title_span["meta"]["metadata"]["session_name"] == "Early title"
    later = proxy._create_llm_span(session, {"messages": []}, {"content": [], "usage": {}}, 2, 1)
    hooks._append_span(later)
    assert later["meta"]["metadata"]["session_name"] == "Early title"


def test_codex_child_name_does_not_become_parent_name():
    hooks = ClaudeHooksAPI()
    codex = CodexHooksAPI(hooks)
    codex._get_or_create_session("parent", 1)
    codex._dispatch("child", {"type": "event_msg", "payload": {"type": "session_name", "name": "Child"}})
    child = {"session_id": "child"}
    hooks._append_span(child)
    codex._set_session_group("child", "parent")
    assert "session_name" not in child["meta"]["metadata"]
    hooks._set_session_name(hooks._sessions["parent"], "Parent")
    assert child["meta"]["metadata"]["session_name"] == "Parent"


def test_codex_index_handles_renames_and_partial_records(tmp_path):
    index = SessionNames(tmp_path / "sessions")
    assert index.refresh() == {}
    index.path.write_text('null\nbad json\n{"id":"one","thread_name":"First"}\n')
    assert index.refresh() == {"one": "First"}
    with index.path.open("a") as source:
        source.write('{"id":"one","thread_name":"Second"}')
    assert index.refresh() == {"one": "First"}
    with index.path.open("a") as source:
        source.write("\n")
    assert index.refresh() == {"one": "Second"}


def test_codex_watcher_sends_name_changes_without_new_rollout_records(tmp_path, monkeypatch):
    path = tmp_path / "rollout.jsonl"
    path.write_text(json.dumps({"type": "session_meta", "payload": {"id": "one", "cwd": str(tmp_path)}}) + "\n")
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._post_record", lambda *args, **kwargs: posts.append(args[2]) or True)
    state = FileState()
    _drain_file(path, state, "http://lapdog", str(tmp_path), session_names={"one": "First"})
    assert posts[0]["payload"] == {"type": "session_name", "name": "First"}
    posts.clear()
    _drain_file(path, state, "http://lapdog", str(tmp_path), session_names={"one": "Second"})
    assert posts == [{"type": "event_msg", "payload": {"type": "session_name", "name": "Second"}}]
    posts.clear()
    _drain_file(path, state, "http://lapdog", str(tmp_path), session_names={"one": "Second"})
    assert posts == []


def test_codex_watcher_retries_failed_name_delivery(tmp_path, monkeypatch):
    path = tmp_path / "rollout.jsonl"
    path.write_text("")
    state = FileState()
    state.session_id = "one"
    state.matches_cwd = True
    monkeypatch.setattr("lapdog.codex_watcher._post_record", lambda *args, **kwargs: False)
    _drain_file(path, state, "http://lapdog", str(tmp_path), session_names={"one": "Name"})
    assert state.session_name == ""
    monkeypatch.setattr("lapdog.codex_watcher._post_record", lambda *args, **kwargs: True)
    _drain_file(path, state, "http://lapdog", str(tmp_path), session_names={"one": "Name"})
    assert state.session_name == "Name"


def test_codex_backfill_reads_name_index(tmp_path, monkeypatch):
    sessions = tmp_path / "sessions"
    sessions.mkdir()
    (sessions / "rollout.jsonl").write_text(
        json.dumps({"type": "session_meta", "payload": {"id": "one", "cwd": str(tmp_path)}}) + "\n"
    )
    (tmp_path / "session_index.jsonl").write_text('{"id":"one","thread_name":"Stored name"}\n')
    posts = []
    monkeypatch.setattr("lapdog.codex_watcher._session.post", lambda *args, **kwargs: posts.append(kwargs["json"]))
    assert backfill_codex.backfill("http://lapdog", cwd=None, session_dir=sessions) == 1
    assert posts[0]["record"]["payload"] == {"type": "session_name", "name": "Stored name"}
    assert all(post["backfill"] for post in posts)
