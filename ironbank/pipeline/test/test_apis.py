#!/usr/bin/env python3

import os
import pytest
import requests
from unittest import mock
from ironbank.pipeline.utils import logger
from ironbank.pipeline.apis import API, VatAPI


log = logger.setup("test_apis")


@pytest.fixture
def mock_api():
    return API(url="http://example.local")


@pytest.fixture
def mock_vat_api():
    return VatAPI(url="http://vat-local.example")


def test_get_image(monkeypatch, caplog, mock_vat_api, mock_responses):  # noqa W0404

    monkeypatch.setattr(requests, "get", mock_responses["200"])
    mock_vat_api.get_image("example/example/example", "1.0")
    assert "Fetched data from vat successfully" in caplog.text
    caplog.clear()

    monkeypatch.setattr(requests, "get", mock_responses["404"])
    mock_vat_api.get_image("example/example/example", "1.0")
    assert "not found in" in caplog.text
    caplog.clear()


@mock.patch.dict(
    os.environ,
    {
        "CI_JOB_JWT_V2": "abcdefg",
        "CI_PROJECT_NAME": "example/example/example",
        "CI_PROJECT_URL": "https://example.invalid",
    },
)
def test_check_access(monkeypatch, caplog, mock_vat_api, mock_responses):  # noqa W0404

    monkeypatch.setattr(requests, "get", mock_responses["200"])
    # mock_vat_api.check_access("example/example/example")
    # for record in caplog.records:
    #     assert record.levelname != "WARNING"
    # caplog.clear()
 
    # monkeypatch.setattr(requests, "get", mock_responses["403"])
    # mock_vat_api.check_access("example/example/example")
    # assert "is not authorized to use the image name of:" in caplog.text
    # caplog.clear()