#!/usr/bin/env python3
import git
import sys
import os
import yaml
import logging
import pathlib
import pytest
from unittest.mock import mock_open

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import trufflehog
from trufflehog import (
    get_commit_diff,
    get_history_cmd,
    create_trufflehog_config,
    get_config,
)  # noqa E402

logging.basicConfig(level="INFO", format="%(levelname)s: %(message)s")


# list of test projects to be cloned and used for testing
@pytest.fixture
def projects():
    return [
        "https://repo1.dso.mil/dsop/opensource/pipeline-test-project/kubectl",
        "https://repo1.dso.mil/dsop/opensource/pipeline-test-project/ubi8",
    ]


# clone test projects and get test repo directories
@pytest.fixture
def test_projects(projects):
    repo_dirs = []
    for project in projects:
        repo_dir = (
            pathlib.Path("test_projects", project.split("/")[-1]).absolute().as_posix()
        )
        # don't clone if already cloned
        git.Repo.clone_from(project, repo_dir) if not pathlib.Path(
            repo_dir
        ).is_dir() else None
        repo_dirs.append(repo_dir)
    return repo_dirs


# test the trufflehog get_history module
# runs by default when running pytest but is excluded from pipeline ci with "not slow"
@pytest.mark.slow
def test_get_history(test_projects):
    for repo_dir in test_projects:
        diff_branch = "origin/master"
        commit_diff = get_commit_diff(repo_dir, diff_branch)
        history_cmd = get_history_cmd(commit_diff)
        logging.info(history_cmd)
        assert (history_cmd[0] == "--since" and history_cmd[1] != "") or history_cmd[
            0
        ] == "--no-history"


# mock output for get_commit_diff, string of commits separated by \n
@pytest.fixture
def commits_string():
    return (
        "e72223cd59700b6dc45bf30d039fa8dd2055d1ec\n"
        "a587dcd3acbf4de15d04da232afa63e3ef310e5d\n"
        "1da1a44a7d300ca2d569b124e8cbd8577e8edf35\n"
        "89555678fe7fe5c60835bf8ceed940368161d06f\n"
        "ada42ed8b621044534e9e7f81faec74c8bcbadd8\n"
        "a6e55bae9d4047c484452c09d849b5dfb44d154e\n"
        "eeb256e29791f840432eeef7ba6c239406fa1c28"
    )


# mock output for get_commit_diff, single commit string
@pytest.fixture
def single_commit():
    return "e72223cd59700b6dc45bf30d039fa8dd2055d1ec"


# mock output for get_commit_diff, empty string (no commit diff)
@pytest.fixture
def empty_string():
    return ""


def test_create_history_message(commits_string, single_commit, empty_string):
    assert get_history_cmd(commits_string) == [
        "--since",
        "eeb256e29791f840432eeef7ba6c239406fa1c28",
    ]
    assert get_history_cmd(single_commit) == [
        "--since",
        "e72223cd59700b6dc45bf30d039fa8dd2055d1ec",
    ]
    assert get_history_cmd(empty_string) == ["--no-history"]


def test_get_commit_diff():
    # TODO implement this
    pass


def test_get_config():
    assert get_config(pathlib.Path("stages/lint/tests/mock/test-th-config.yaml")) == [
        {
            "message": "Standard pipeline config",
            "paths": ["stages/lint/README.md"],
            "pattern": "airflow_conf_set",
        }
    ]

    # TODO finish this test
    # assert get_config(Path("")) == None


def test_create_trufflehog_config(monkeypatch):
    monkeypatch.setattr(trufflehog, "get_config", lambda *args, **kwargs: [])
    monkeypatch.setattr(pathlib.Path, "open", mock_open(read_data="data"))
    monkeypatch.setattr(yaml, "safe_dump", lambda *args, **kwargs: True)
    assert (
        create_trufflehog_config(
            pathlib.Path("stages/lint/tests/mock/test-th-config-concat.yaml"),
            pathlib.Path("stages/lint/tests/mock/test-th-config.yaml"),
            "./",
            ["TRUFFLEHOG"],
        )
        == True  # noqa E712
    )
    assert (
        create_trufflehog_config(
            pathlib.Path("stages/lint/tests/mock/test-th-config-concat.yaml"),
            pathlib.Path("stages/lint/tests/mock/test-th-config.yaml"),
            "./",
        )
        == False  # noqa E712
    )
