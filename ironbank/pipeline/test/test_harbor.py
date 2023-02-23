#!/usr/bin/env python3

from ironbank.pipeline.test.mocks.mock_classes import MockPaginatedRequest
from ironbank.pipeline.harbor import HarborProject, HarborRepository
from ironbank.pipeline.utils import logger
from unittest.mock import patch
from requests import Session


log = logger.setup("test_harbor")

harbor_session = Session()
harbor_session.auth = ("user", "password")


@patch("ironbank.pipeline.harbor.PaginatedRequest", new=MockPaginatedRequest)
def test_harbor_project(monkeypatch):  # noqa W0404
    log.info("Test successful get_project_repository")
    monkeypatch.setattr(
        MockPaginatedRequest,
        "get",
        lambda x: [{"name": "test/ironbank"}, {"name": "test/ironbank"}],
    )

    harbor_project = HarborProject(harbor_session, name="ironbank")
    harbor_project.get_project_repository(all=True)
    for harbor_repo in harbor_project.repositories:
        assert "ironbank" in harbor_repo.name


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
