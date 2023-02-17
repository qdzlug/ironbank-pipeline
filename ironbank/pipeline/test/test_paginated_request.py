#!/usr/bin/env python3

import pytest
import requests

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.paginated_request import PaginatedRequest
from requests import Session
from ironbank.pipeline.utils.exceptions import MaxRetriesException

log = logger.setup("test_harbor_api")

harbor_session = Session()
harbor_session.auth = ("user", "password")


def test_paginated_request(monkeypatch, caplog, mock_responses):  # noqa W0404
    monkeypatch.setattr(
        Session, "get", mock_responses["mock200_with_x_total_count_headers_and_pages"]
    )

    paginated_req = PaginatedRequest(session=harbor_session, url="https://example")
    log.info("Successful Paginated Request initialization")
    monkeypatch.setattr(Session, "get", mock_responses["500"])

    try:
        PaginatedRequest(session=harbor_session, url="https://example")
    except Exception as e:
        log.info("Unsuccessful Paginated Request initialization")

    monkeypatch.setattr(
        Session, "get", mock_responses["mock200_with_x_total_count_headers_and_pages"]
    )
    paginated_req.get()

    log.info("Successful Harbor API get")

    monkeypatch.setattr(Session, "get", mock_responses["500"])
    try:
        PaginatedRequest(session=harbor_session, url="https://example")
    except Exception as e:
        log.info("Unsuccessful Paginated Request initialization")
