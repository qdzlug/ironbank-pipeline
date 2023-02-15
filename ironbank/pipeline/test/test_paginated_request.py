#!/usr/bin/env python3

import pytest
import requests

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.paginated_request import PaginatedRequest

log = logger.setup("test_harbor_api")


@pytest.fixture
def mock_paginated_request():
    return PaginatedRequest(auth=[],url = "")

# PaginatedRequest
def test_get_project_repository(monkeypatch, caplog, mock_response):  # noqa W0404

    monkeypatch.setattr(requests, "get",  mock_response["mock200_with_x_total_count_headers"])
    mock_paginated_request.get()
    # assert "Successfully Retrieved Harbor Project" in caplog.text
    # caplog.clear()

    # monkeypatch.setattr(requests, "get", mock_get_project_repository_response_404)
    # try:
    #     mock_project.get_project_repository("example/example/example")
    # except requests.exceptions.HTTPError:
    #     assert "Error while retrieving Harbor Project" in caplog.text
    #     caplog.clear()


# def test_get_repository_artifact(monkeypatch, caplog, mock_repository):  # noqa W0404
#     monkeypatch.setattr(requests, "get", mock_get_repository_artifact_response_200)
#     mock_repository.get_repository_artifact("example/example/example")
#     assert "Successfully Retrieved Harbor Repository" in caplog.text
#     caplog.clear()

#     monkeypatch.setattr(requests, "get", mock_get_repository_artifact_response_404)
#     try:
#         mock_repository.get_repository_artifact("example/example/example")
#     except requests.exceptions.HTTPError:
#         assert "Error" in caplog.text
#         caplog.clear()
