#!/usr/bin/env python3

from ironbank.pipeline.test.mocks.mock_classes import (
    MockPaginatedRequest,
    MockSession,
    MockHarborRobot,
    MockHarborRobotPermissions,
    MockResponse,
)
from ironbank.pipeline.harbor import (
    HarborProject,
    HarborRepository,
    HarborSystem,
    HarborRobot,
    HarborRobotPermissions,
)
from ironbank.pipeline.utils import logger
from unittest.mock import patch


log = logger.setup("test_harbor")


@patch("ironbank.pipeline.harbor.PaginatedRequest", new=MockPaginatedRequest)
def test_harbor_system_project(monkeypatch):  # noqa W0404
    log.info("Test successful projects retrieval")
    monkeypatch.setattr(
        MockPaginatedRequest,
        "get",
        lambda x: [{"name": "goo-goo-dolls"}, {"name": "ironbank"}],
    )
    harbor_system = HarborSystem(MockSession())
    harbor_system.get_projects()
    assert "goo-goo-dolls" in harbor_system.projects[0].name
    assert "ironbank" in harbor_system.projects[1].name


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
    harbor_repository = HarborRepository(session=MockSession(), name="ironbank")
    harbor_repository.get_repository_artifact(all=True)
    assert "test" == harbor_repository.artifacts[0].digest
    assert harbor_repository.artifacts[1].tags is None


@patch("ironbank.pipeline.harbor.HarborRobot", MockHarborRobot)
def test_harbor_robot_payload():  # noqa W0404
    log.info("Test generation of robot account payload")
    hr = HarborRobot(permissions=[MockHarborRobotPermissions().__dict__])
    for permission in hr.permissions:
        assert isinstance(permission, HarborRobotPermissions)
    payload = hr.payload()
    assert payload["name"] == HarborRobot.name


@patch("ironbank.pipeline.harbor.HarborRobot", MockHarborRobot)
def test_harbor_robot_create(monkeypatch, mock_responses):
    log.info("Test generation of robot account creation success")
    hr = HarborRobot(
        permissions=[MockHarborRobotPermissions().__dict__], session=MockSession()
    )
    monkeypatch.setattr(MockSession, "post", mock_responses["200"])
    resp = hr.create_robot()
    assert resp["text"] == "successful_request"


@patch("ironbank.pipeline.harbor.PaginatedRequest", new=MockPaginatedRequest)
def test_harbor_robots(monkeypatch):  # noqa W0404
    log.info("Test get harbor project robots")
    monkeypatch.setattr(
        MockPaginatedRequest,
        "get",
        lambda x: [
            {"name": "robot1", "description": "test robot", "expires_at": "2022-01-01"},
            {"name": "robot2", "description": "test robot", "expires_at": "2023-01-01"},
            {"name": "robot2", "expires_at": "2023-01-01"},
        ],
    )

    harbor_project = HarborProject(name="nonsense", session=MockSession())
    harbor_project.get_robot_accounts()
    assert "robot1" == harbor_project.robots[0].name
    assert "test robot" == harbor_project.robots[1].description
    assert "" == harbor_project.robots[2].description

    log.info("Test get harbor system robots")
    harbor_system = HarborSystem(session=MockSession())
    harbor_system.get_robot_accounts()
    assert "robot1" == harbor_system.robots[0].name
    assert "test robot" == harbor_system.robots[1].description
    assert "" == harbor_project.robots[2].description
