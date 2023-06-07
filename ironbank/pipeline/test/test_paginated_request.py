#!/usr/bin/env python3

import pytest
from requests import HTTPError

from ironbank.pipeline.test.mocks.mock_classes import MockSession
from ironbank.pipeline.utils import decorators, logger
from ironbank.pipeline.utils.exceptions import MaxRetriesException
from ironbank.pipeline.utils.paginated_request import PaginatedRequest

log = logger.setup("test_paginated_request")


def test_paginated_request_init(monkeypatch, mock_responses):  # noqa W0404
    log.info("Test successful init")
    monkeypatch.setattr(
        MockSession,
        "get",
        mock_responses["mock200_with_x_total_count_headers_and_pages"],
    )
    paginated_req = PaginatedRequest(session=MockSession(), url="https://example")
    assert paginated_req.url == "https://example"

    log.info("Test unsuccessful init forces max retries")
    monkeypatch.setattr(MockSession, "get", mock_responses["500"])
    monkeypatch.setattr(decorators, "request_retry", None)
    with pytest.raises(MaxRetriesException):
        PaginatedRequest(session=MockSession(), url="https://example")


def test_paginated_request_get(monkeypatch, mock_responses):  # noqa W0404
    log.info("Test successful get")
    monkeypatch.setattr(
        MockSession,
        "get",
        mock_responses["mock200_with_x_total_count_headers_and_pages"],
    )
    paginated_req = PaginatedRequest(session=MockSession(), url="https://example")
    assert paginated_req.url == "https://example"
    for response in paginated_req.get():
        assert response["status_code"] == 200
        assert response["text"] == "successful_request"

    log.info("Test raise HTTPError")
    monkeypatch.setattr(MockSession, "get", mock_responses["500"])
    # Mock post init to not raise MaxRetriesException due to Session.get mock above
    monkeypatch.setattr(PaginatedRequest, "__post_init__", lambda x: None)
    paginated_req = PaginatedRequest(session=MockSession(), url="https://example")
    paginated_req.total_pages = 1
    with pytest.raises(HTTPError):
        next(paginated_req.get())
