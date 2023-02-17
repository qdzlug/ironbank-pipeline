#!/usr/bin/env python3

from ironbank.pipeline.utils import logger
from requests import Session
from ironbank.pipeline.utils import decorators
import pytest
from ironbank.pipeline.utils.paginated_request import PaginatedRequest
from ironbank.pipeline.utils.exceptions import (
    MaxRetriesException,
)


log = logger.setup("test_paginated_request")

harbor_session = Session()
harbor_session.auth = ("user", "password")


def test_paginated_request_init(monkeypatch, mock_responses):  # noqa W0404
    log.info("Test successful init")
    monkeypatch.setattr(
        Session, "get", mock_responses["mock200_with_x_total_count_headers_and_pages"]
    )
    paginated_req = PaginatedRequest(session=harbor_session, url="https://example")
    assert paginated_req.url == "https://example"

    log.info("Test unsuccessful init forces max retries")
    monkeypatch.setattr(Session, "get", mock_responses["500"])
    monkeypatch.setattr(decorators, "request_retry", None)
    with pytest.raises(MaxRetriesException):
        PaginatedRequest(session=harbor_session, url="https://example")


def test_paginated_request_get(monkeypatch, mock_responses):  # noqa W0404
    monkeypatch.setattr(
        Session, "get", mock_responses["mock200_with_x_total_count_headers_and_pages"]
    )

    paginated_req = PaginatedRequest(session=harbor_session, url="https://example")
    assert paginated_req.url == "https://example"
    for item in paginated_req.get():
        assert item["status_code"] == 200
        assert item["text"] == "successful_request"

    # monkeypatch.setattr(
    #     Session, "get", mock_responses["mock200_with_x_total_count_headers_and_pages"]
    # )
    # paginated_req.total_pages = 10
    # paginated_req.get()

    # log.info("Successful Paginated Request  get")

    # monkeypatch.setattr(Session, "get", mock_responses["500"])
    # try:
    #     PaginatedRequest(session=harbor_session, url="https://example")
    # except Exception:
    #     log.info("Unsuccessful Paginated Request get")
