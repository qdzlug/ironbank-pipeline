#!/usr/bin/env python3

import pytest

from ironbank.pipeline.utils import logger
from ironbank.pipeline.harbor import HarborProject, HarborRepository, HarborRobots
from ironbank.pipeline.test.mocks.mock_classes import MockPaginatedRequest
from unittest.mock import patch
from requests import Session


log = logger.setup("test_harbor_api")

harbor_session = Session()
harbor_session.auth = ("user", "password")


@pytest.fixture
def mock_page():
    return {"name": "ironbank"}


@pytest.fixture
def mock_artifact():
    return {
        "digest": "digest",
        "tags": "tags",
        "project": "project",
        "repository": "repository",
        "push_time": "push_time",
    }


@patch("ironbank.pipeline.harbor.PaginatedRequest", new=MockPaginatedRequest)
def test_harbor_project(monkeypatch):  # noqa W0404
    monkeypatch.setattr(
        MockPaginatedRequest,
        "get",
        lambda x: [{"name": "ironbank"}, {"name": "ironbank"}],
    )

    ironbank = HarborProject(harbor_session, name="ironbank")
    ironbank.get_project_repository(all=True)
    log.info("Successful Harbor Project Repo get")


@patch("ironbank.pipeline.harbor.PaginatedRequest", new=MockPaginatedRequest)
def test_harbor_artifact(monkeypatch):  # noqa W0404
    monkeypatch.setattr(
        MockPaginatedRequest,
        "get",
        lambda x: [
            {
                "digest": "digest",
                "tags": "tags",
                "project": "project",
                "repository": "repository",
                "push_time": "push_time",
            },
            {
                "digest": "digest",
                "tags": "tags",
                "project": "project",
                "repository": "repository",
                "push_time": "push_time",
            },
        ],
    )

    ironbank = HarborRepository(harbor_session, name="ironbank")
    ironbank.get_repository_artifact()
    log.info("Successful Harbor Artifact get")


@patch("ironbank.pipeline.harbor.PaginatedRequest", new=MockPaginatedRequest)
def test_harbor_robots(monkeypatch):  # noqa W0404
    monkeypatch.setattr(
        MockPaginatedRequest,
        "get",
        lambda x: [
            {"name": "robot1", "description": "test robot", "expires_at": "2022-01-01"},
            {"name": "robot2", "description": "test robot", "expires_at": "2023-01-01"},
        ],
    )

    ironbank = HarborRobots(harbor_session)
    ironbank.get_accounts()
    log.info("Successful Harbor Robots get")
