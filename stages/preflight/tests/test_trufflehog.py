#!/usr/bin/env python3
import git
import sys
import os
import logging
import pathlib
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from trufflehog import get_history_cmd, create_history_msg  # noqa E402

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
@pytest.mark.slow
def test_get_history(test_projects):
    for repo_dir in test_projects:
        diff_branch = "origin/master"
        history_cmd = get_history_cmd(repo_dir, diff_branch)
        logging.info(history_cmd)
        assert (
            history_cmd[0] == "--since-commit" and history_cmd[1] != ""
        ) or history_cmd[0] == "--no-history"


@pytest.fixture
def commits_string():
    return "e72223cd59700b6dc45bf30d039fa8dd2055d1ec\na587dcd3acbf4de15d04da232afa63e3ef310e5d\n1da1a44a7d300ca2d569b124e8cbd8577e8edf35\n89555678fe7fe5c60835bf8ceed940368161d06f\nada42ed8b621044534e9e7f81faec74c8bcbadd8\na6e55bae9d4047c484452c09d849b5dfb44d154e\neeb256e29791f840432eeef7ba6c239406fa1c28"


@pytest.fixture
def single_commit():
    return "e72223cd59700b6dc45bf30d039fa8dd2055d1ec"


@pytest.fixture
def empty_string():
    return ""


def test_create_history_message(commits_string, single_commit, empty_string):
    assert create_history_msg(commits_string) == [
        "--since-commit",
        "eeb256e29791f840432eeef7ba6c239406fa1c28",
    ]
    assert create_history_msg(single_commit) == [
        "--since-commit",
        "e72223cd59700b6dc45bf30d039fa8dd2055d1ec",
    ]
    assert create_history_msg(empty_string) == ["--no-history"]
