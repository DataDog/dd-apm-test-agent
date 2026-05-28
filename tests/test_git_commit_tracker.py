import gzip
import subprocess
import time

import msgpack
import pytest

from ddapm_test_agent.agent import make_app
from ddapm_test_agent.git_commit_tracker import GitCommitTracker
from ddapm_test_agent.git_commit_tracker import build_tracker_from_env
from ddapm_test_agent.llmobs_event_platform import apply_git_commit_tags


def _git(repo, *args):
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True, text=True)


def _rev_parse(repo):
    return subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def git_repo(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init")
    _git(repo, "config", "user.email", "qa@local")
    _git(repo, "config", "user.name", "QA")
    (repo / "README.md").write_text("# repo\n")
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", "initial commit")
    return str(repo)


def _commit(repo, name, content="x"):
    from pathlib import Path

    Path(repo, name).write_text(content)
    _git(repo, "add", "-A")
    _git(repo, "commit", "-m", f"add {name}")
    return _rev_parse(repo)


# --- GitCommitTracker unit tests -------------------------------------------


def test_is_git_repo_true(git_repo):
    tracker = GitCommitTracker(git_repo)
    assert tracker.is_git_repo() is True


def test_is_git_repo_false(tmp_path):
    tracker = GitCommitTracker(str(tmp_path))
    assert tracker.is_git_repo() is False
    # sha_at on a non-repo must not raise and returns None.
    assert tracker.sha_at(time.time_ns()) is None


def test_sha_at_tracks_head_across_commits(git_repo):
    c0 = _rev_parse(git_repo)
    tracker = GitCommitTracker(git_repo, poll_interval=0.1)
    tracker.start()
    try:
        time.sleep(0.25)
        t_before = time.time_ns()
        time.sleep(0.1)
        c1 = _commit(git_repo, "hello.py")
        time.sleep(0.3)
        t_after = time.time_ns()

        assert tracker.sha_at(t_before) == c0
        assert tracker.sha_at(t_after) == c1
        # The tagged SHA only ever moves forward in time.
        transitions = tracker.transitions()
        assert [sha for _, sha in transitions] == [c0, c1]
    finally:
        tracker.stop()


def test_sha_at_predating_first_observation_falls_back(git_repo):
    tracker = GitCommitTracker(git_repo, poll_interval=0.1)
    tracker.start()
    try:
        time.sleep(0.2)
        # A timestamp far in the past predates any observation and any commit
        # date -> falls back to the earliest known SHA rather than raising.
        assert tracker.sha_at(1_000 * 1_000_000_000) == _rev_parse(git_repo)
    finally:
        tracker.stop()


def test_repository_url(git_repo):
    tracker = GitCommitTracker(git_repo)
    assert tracker.is_git_repo()
    assert tracker.repository_url is None  # no remote configured
    _git(git_repo, "remote", "add", "origin", "https://github.com/acme/widgets.git")
    tracker2 = GitCommitTracker(git_repo)
    assert tracker2.is_git_repo()
    assert tracker2.repository_url == "https://github.com/acme/widgets.git"


# --- apply_git_commit_tags --------------------------------------------------


def test_apply_git_commit_tags_idempotent(git_repo):
    tracker = GitCommitTracker(git_repo, poll_interval=0.1)
    tracker.start()
    try:
        time.sleep(0.2)
        sha = _rev_parse(git_repo)
        spans = [{"start_ns": time.time_ns(), "tags": ["env:test"]}]
        apply_git_commit_tags(spans, tracker)
        apply_git_commit_tags(spans, tracker)  # second call must not duplicate
        tags = spans[0]["tags"]
        assert tags.count(f"git.commit.sha:{sha}") == 1
        assert "env:test" in tags
    finally:
        tracker.stop()


def test_apply_git_commit_tags_includes_repo_url(git_repo):
    _git(git_repo, "remote", "add", "origin", "git@github.com:acme/widgets.git")
    tracker = GitCommitTracker(git_repo, poll_interval=0.1)
    tracker.start()
    try:
        time.sleep(0.2)
        spans = [{"start_ns": time.time_ns(), "tags": []}]
        apply_git_commit_tags(spans, tracker)
        assert "git.repository_url:git@github.com:acme/widgets.git" in spans[0]["tags"]
    finally:
        tracker.stop()


# --- build_tracker_from_env -------------------------------------------------


def test_build_tracker_from_env_disabled_when_not_lapdog():
    assert build_tracker_from_env(lapdog_mode=False) is None


def test_build_tracker_from_env_toggle_off(git_repo, monkeypatch):
    monkeypatch.setenv("LAPDOG_GIT_REPO", git_repo)
    monkeypatch.setenv("LAPDOG_GIT_COMMIT_TAGGING", "0")
    assert build_tracker_from_env(lapdog_mode=True) is None


def test_build_tracker_from_env_non_repo(tmp_path, monkeypatch):
    monkeypatch.setenv("LAPDOG_GIT_REPO", str(tmp_path))
    monkeypatch.delenv("LAPDOG_GIT_COMMIT_TAGGING", raising=False)
    assert build_tracker_from_env(lapdog_mode=True) is None


def test_build_tracker_from_env_enabled(git_repo, monkeypatch):
    monkeypatch.setenv("LAPDOG_GIT_REPO", git_repo)
    monkeypatch.delenv("LAPDOG_GIT_COMMIT_TAGGING", raising=False)
    tracker = build_tracker_from_env(lapdog_mode=True)
    assert tracker is not None
    assert tracker.is_git_repo()


# --- end-to-end through the LLMObs intake + query path ----------------------


def _make_lapdog_app(git_repo, **overrides):
    kwargs = dict(
        enabled_checks=[],
        log_span_fmt="[{name}]",
        snapshot_dir="snapshots",
        snapshot_ci_mode=False,
        snapshot_ignored_attrs=[],
        agent_url="",
        trace_request_delay=0.0,
        suppress_trace_parse_errors=False,
        pool_trace_check_failures=False,
        disable_error_responses=False,
        snapshot_removed_attrs=[],
        snapshot_regex_placeholders={},
        vcr_cassettes_directory="vcr-cassettes",
        vcr_ci_mode=False,
        vcr_provider_map="",
        vcr_ignore_headers="",
        vcr_json_body_normalizers="",
        dd_site="datadoghq.com",
        dd_api_key=None,
        disable_llmobs_data_forwarding=True,
        lapdog_mode=True,
    )
    kwargs.update(overrides)
    return make_app(**kwargs)


async def test_intake_to_query_tags_spans_with_commit_sha(git_repo, monkeypatch, aiohttp_client):
    monkeypatch.setenv("LAPDOG_GIT_REPO", git_repo)
    monkeypatch.delenv("LAPDOG_GIT_COMMIT_TAGGING", raising=False)

    app = _make_lapdog_app(git_repo)
    client = await aiohttp_client(app)

    sha = _rev_parse(git_repo)
    payload = {
        "ml_app": "lapdog",
        "spans": [
            {
                "name": "agent-workflow",
                "span_id": "s1",
                "trace_id": "t1",
                "parent_id": "undefined",
                "start_ns": time.time_ns(),
                "meta": {"span": {"kind": "agent"}},
                "metrics": {},
                "tags": [],
            }
        ],
    }
    resp = await client.post(
        "/evp_proxy/v2/api/v2/llmobs",
        headers={"Content-Type": "application/msgpack", "Content-Encoding": "gzip"},
        data=gzip.compress(msgpack.packb(payload)),
    )
    assert resp.status == 200

    resp = await client.post(
        "/api/unstable/llm-obs-query-rewriter/list?type=llmobs",
        json={"list": {"limit": 100, "sort": {"time": {"order": "asc"}}}},
    )
    assert resp.status == 200, await resp.text()
    body = await resp.json()
    events = body.get("result", {}).get("events", [])
    assert events, body
    all_tags = []
    for ev in events:
        all_tags.extend(ev.get("tags", []))
        all_tags.extend(ev.get("event", {}).get("custom", {}).get("tags", []))
    assert f"git.commit.sha:{sha}" in all_tags
