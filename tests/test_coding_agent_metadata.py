import dataclasses
import subprocess

from ddapm_test_agent.coding_agent_metadata import _local_git_metadata
from ddapm_test_agent.coding_agent_metadata import normalize_git_repository_url
from ddapm_test_agent.coding_agent_metadata import project_metadata_tags
from ddapm_test_agent.coding_agent_metadata import project_name_from_git_repository_url
from ddapm_test_agent.coding_agent_metadata import resolve_project_metadata


def test_normalize_git_repository_url_formats():
    assert (
        normalize_git_repository_url("https://token@github.com/DataDog/dd-trace-py.git")
        == "github.com/DataDog/dd-trace-py"
    )
    assert normalize_git_repository_url("git@github.com:DataDog/dd-apm-test-agent.git") == (
        "github.com/DataDog/dd-apm-test-agent"
    )
    assert normalize_git_repository_url("ssh://git@github.com/DataDog/dd-trace-py.git") == (
        "github.com/DataDog/dd-trace-py"
    )
    assert normalize_git_repository_url("github.com/DataDog/dd-trace-py.git") == "github.com/DataDog/dd-trace-py"


def test_project_name_from_git_repository_url():
    assert project_name_from_git_repository_url("git@github.com:DataDog/dd-apm-test-agent.git") == "dd-apm-test-agent"


def test_resolve_project_metadata_prefers_project_name_and_omits_commit(monkeypatch, tmp_path):
    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()

    meta = resolve_project_metadata(
        cwd=str(tmp_path),
        project_name="agent-project",
        git_repository_url="https://github.com/DataDog/dd-trace-py.git",
    )

    assert meta.project_name == "agent-project"
    assert meta.git_repository_url == "github.com/DataDog/dd-trace-py"
    assert project_metadata_tags(meta) == [
        "project_name:agent-project",
        "git.repository_url:github.com/DataDog/dd-trace-py",
    ]
    assert not any("commit" in key for key in dataclasses.asdict(meta))


def test_resolve_project_metadata_uses_local_git_fallback(monkeypatch, tmp_path):
    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()
    subprocess.run(["git", "init"], cwd=tmp_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/DataDog/dd-apm-test-agent.git"],
        cwd=tmp_path,
        check=True,
        capture_output=True,
    )
    nested = tmp_path / "nested"
    nested.mkdir()

    meta = resolve_project_metadata(cwd=str(nested))

    assert meta.project_name == "dd-apm-test-agent"
    assert meta.git_repository_url == "github.com/DataDog/dd-apm-test-agent"


def test_resolve_project_metadata_falls_back_to_cwd_name(monkeypatch, tmp_path):
    monkeypatch.delenv("DD_GIT_REPOSITORY_URL", raising=False)
    _local_git_metadata.cache_clear()
    cwd = tmp_path / "plain-project"
    cwd.mkdir()

    meta = resolve_project_metadata(cwd=str(cwd))

    assert meta.project_name == "plain-project"
    assert meta.git_repository_url == ""
