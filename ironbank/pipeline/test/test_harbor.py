#!/usr/bin/env python3

from ironbank.pipeline.test.mocks.mock_classes import MockPaginatedRequest, MockSession
from ironbank.pipeline.harbor import HarborProject, HarborRepository, HarborRobots
from ironbank.pipeline.utils import logger
from unittest.mock import patch


log = logger.setup("test_harbor")


@patch("ironbank.pipeline.harbor.PaginatedRequest", new=MockPaginatedRequest)
def test_harbor_project(monkeypatch):  # noqa W0404
    log.info("Test successful get all repositories")
    monkeypatch.setattr(
        MockPaginatedRequest,
        "get",
        lambda x: [{"name": "test/ironbank"}, {"name": "next/ironbank"}],
    )
    harbor_project = HarborProject(MockSession(), name="ironbank")
    harbor_project.get_project_repository(all=True)
    for harbor_repo in harbor_project.repositories:
        assert "ironbank" in harbor_repo.name


@patch("ironbank.pipeline.harbor.PaginatedRequest", new=MockPaginatedRequest)
def test_harbor_repository(monkeypatch):  # noqa W0404
    log.info("Test get all repo artifacts")
    monkeypatch.setattr(
        MockPaginatedRequest,
        "get",
        lambda x: [
            {
                "digest": "test",
                "tags": "tags",
                "project": "project",
                "repository": "repository",
                "push_time": "push_time",
            },
            {
                "digest": "test",
                "project": "project",
                "repository": "repository",
                "push_time": "push_time",
            },
        ],
    )
    harbor_repository = HarborRepository(MockSession(), name="ironbank")
    harbor_repository.get_repository_artifact(all=True)
    assert "test" == harbor_repository.artifacts[0].digest
    assert harbor_repository.artifacts[1].tags is None


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

    ironbank = HarborRobots(MockSession())
    ironbank.get_accounts()
    log.info("Successful Harbor Robots get")
