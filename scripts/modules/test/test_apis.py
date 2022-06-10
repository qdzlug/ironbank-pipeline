import os
import sys
import logging
from unittest import mock
import pytest
import requests
from dataclasses import dataclass

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from apis import API, VatAPI  # noqa E402
from utils import logger  # noqa E402
from mocks.mock_responses import mock_responses  # noqa E402 W0611
from utils.decorators import request_error_handler


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
    mock_vat_api.check_access("example/example/example")
    for record in caplog.records:
        assert record.levelname != "WARNING"
    caplog.clear()

    monkeypatch.setattr(requests, "get", mock_responses["403"])
    mock_vat_api.check_access("example/example/example")
    assert "is not authorized to use the image name of:" in caplog.text
    caplog.clear()
