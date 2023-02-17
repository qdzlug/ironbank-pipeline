#!/usr/bin/env python3

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.paginated_request import PaginatedRequest
from requests import Session
from unittest.mock import patch

log = logger.setup("test_harbor_api")

harbor_session = Session()
harbor_session.auth = ("user", "password")

@patch("ironbank.pipeline.utils.paginated_request.Session", new=Session)
def test_paginated_request_init(monkeypatch, mock_responses):  # noqa W0404
    monkeypatch.setattr(
        Session, "get", mock_responses["mock200_with_x_total_count_headers_and_pages"]
    )

    PaginatedRequest(session=harbor_session, url="https://example")
    log.info("Successful Paginated Request initialization")
    monkeypatch.setattr(Session, "get", mock_responses["500"])

    try:
        PaginatedRequest(session=harbor_session, url="https://example")
    except Exception:
        log.info("Unsuccessful Paginated Request initialization")

    
@patch("ironbank.pipeline.utils.paginated_request.Session", new=Session)
def test_paginated_request(monkeypatch, mock_responses):  # noqa W0404
    monkeypatch.setattr(
        Session, "get", mock_responses["mock200_with_x_total_count_headers_and_pages"]
    )

    paginated_req = PaginatedRequest(session=harbor_session, url="https://example")
   

    monkeypatch.setattr(
        Session, "get", mock_responses["mock200_with_x_total_count_headers_and_pages"]
    )
    paginated_req.total_pages = 10
    paginated_req.get()

    log.info("Successful Paginated Request  get")

    monkeypatch.setattr(Session, "get", mock_responses["500"])
    try:
        PaginatedRequest(session=harbor_session, url="https://example")
    except Exception:
        log.info("Unsuccessful Paginated Request get")
