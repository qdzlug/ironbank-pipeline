#!/usr/bin/env python3
from dataclasses import dataclass
import sys
from unittest.mock import patch
from pathlib import Path

import subprocess
from subprocess import CalledProcessError
import pytest
import yaml

from common.utils import logger
from pipeline.test.mocks.mock_classes import (
    MockPath,
    MockCompletedProcess,
)


sys.path.append(Path(__file__).absolute().parents[1].as_posix())
import trufflehog  # noqa E402

log = logger.setup("test_trufflehog")

mock_path = Path(__file__).absolute().parent


class MockGit:
    def rev_list(self, *args, **kwargs):
        if len(args) == 0:
            return ""
        if args[0] == "feature_branch..":
            return "commit_sha_1\ncommit_sha_2\ncommit_sha_3"
        elif args[0] == "development..":
            return "commit_sha_4\ncommit_sha_5"


@dataclass
class MockGitRepo:
    repo_dir: str
    git: MockGit = MockGit()


@patch("trufflehog.Repo", new=MockGitRepo)
def test_get_commit_diff():
    repo_dir = "/path/to/repo"
    feature_branch = "feature_branch"
    commits = trufflehog.get_commit_diff(repo_dir, feature_branch)
    log.info("Testing commit diff function")
    assert commits == "commit_sha_1\ncommit_sha_2\ncommit_sha_3"


def test_get_history_cmd():
    commits = "commit_sha_1\ncommit_sha_2\ncommit_sha_3"
    results = trufflehog.get_history_cmd(commits)
    log.info("Testing get_history_cmd functionality with valid string arguments")
    assert results == ["--since", "commit_sha_3"]
    results = trufflehog.get_history_cmd("")
    log.info("Testing get_history_cmd functionality with empty string argument")
    assert results == ["--no-history"]


@patch("trufflehog.Path", new=MockPath)
def test_get_config(monkeypatch):
    monkeypatch.setattr(
        yaml,
        "safe_load",
        lambda *args, **kwargs: {
            "exclude": [
                {"name": "Example1", "paths": ["/path/to/exclude1"]},
                {
                    "name": "Example2",
                    "paths": ["/path/to/exclude2", "/path/to/exclude3"],
                },
            ]
        },
    )
    # Testing result if file not found
    result = trufflehog.get_config(MockPath("."), False)
    assert result == []

    monkeypatch.setattr(MockPath, "is_file", lambda *args, **kwargs: True)
    result = trufflehog.get_config(MockPath("."), True)
    log.info("Testing get_config for valid return value")
    assert result == [
        {"name": "Example1", "paths": ["/path/to/exclude1"]},
        {
            "name": "Example2",
            "paths": ["/path/to/exclude2", "/path/to/exclude3"],
        },
    ]


@patch("trufflehog.Path", new=MockPath)
def test_create_trufflehog_config(monkeypatch):
    monkeypatch.setattr(
        yaml,
        "safe_load",
        lambda *args, **kwargs: {
            "exclude": [
                {"name": "Example1", "paths": ["/path/to/exclude1"]},
                {
                    "name": "Example2",
                    "paths": ["/path/to/exclude2", "/path/to/exclude3"],
                },
            ]
        },
    )
    monkeypatch.setattr(
        yaml,
        "safe_dump",
        lambda *args, **kwargs: None,
    )
    result = trufflehog.create_trufflehog_config(
        MockPath("project"), MockPath("default"), "/path/to/repo"
    )
    assert result == False
    log.info("Setting the is_file function to true for code coverage")
    monkeypatch.setattr(MockPath, "is_file", lambda *args, **kwargs: True)
    result = trufflehog.create_trufflehog_config(
        MockPath("project"), MockPath("default"), "/path/to/repo", "True"
    )
    assert result == True


@patch("trufflehog.Path", new=MockPath)
def test_main(monkeypatch, raise_):
    monkeypatch.setenv("CI_PROJECT_DIR", "mock_CI_PROJECT_DIR")
    monkeypatch.setenv("PIPELINE_REPO_DIR", "mock_PIPELINE_REPO_DIR")
    monkeypatch.setenv("CI_COMMIT_BRANCH", "mock_CI_COMMIT_BRANCH")
    monkeypatch.setenv("CI_JOB_IMAGE", "mock_CI_JOB_IMAGE")
    monkeypatch.setenv("TRUFFLEHOG_CONFIG", "mock_TRUFFLEHOG_CONFIG")
    monkeypatch.setenv("TRUFFLEHOG_TARGET", "pipeline")

    monkeypatch.setattr(trufflehog, "get_commit_diff", lambda *args, **kwargs: "")
    monkeypatch.setattr(trufflehog, "get_history_cmd", lambda *args, **kwargs: [])
    monkeypatch.setattr(
        trufflehog, "create_trufflehog_config", lambda *args, **kwargs: True
    )
    log.info("Mocking is_file return value to true for trufflehog.yaml file")
    monkeypatch.setattr(MockPath, "is_file", lambda *args, **kwargs: True)
    log.info("asserting the existence of a trufflehog.yaml file causes a system exit")
    with pytest.raises(SystemExit):
        trufflehog.main()
    ## Testing different return codes. Coverage for if/else statements embedded in the try/except blocks

    monkeypatch.setattr(MockPath, "is_file", lambda *args, **kwargs: False)

    log.info("Testing for system exit with non-zero return code from subprocess")
    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *args, **kwargs: MockCompletedProcess(returncode=1),
        )
        trufflehog.main()

    log.info(
        "Testing for system exit with non-zero return code from subprocess. Entering nested if/else statements"
    )
    with pytest.raises(SystemExit):
        monkeypatch.setenv("TRUFFLEHOG_TARGET", "mock_TRUFFLEHOG_TARGET")
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *args, **kwargs: raise_(
                CalledProcessError(returncode=2, cmd="", output="this is an error")
            ),
        )
        trufflehog.main()

    log.info("Testing for system exit with non-zero return code from subprocess")
    with pytest.raises(SystemExit):
        monkeypatch.setattr(
            subprocess,
            "run",
            lambda *args, **kwargs: raise_(
                CalledProcessError(returncode=1, cmd="", output="this is an error")
            ),
        )
        trufflehog.main()

    log.info("Mocking subprocess return code to 0, implying successful code execution")
    monkeypatch.setattr(
        subprocess, "run", lambda *args, **kwargs: MockCompletedProcess(returncode=0)
    )
    monkeypatch.setattr(
        trufflehog, "create_trufflehog_config", lambda *args, **kwargs: False
    )
    monkeypatch.setenv("CI_COMMIT_BRANCH", "development")

    trufflehog.main()
