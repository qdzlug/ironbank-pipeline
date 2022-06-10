import os
import sys
import logging
from unittest import mock
import pytest
import requests
from dataclasses import dataclass

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from apis import API, VatAPI, request_error_handler  # noqa E402
from utils import logger  # noqa E402
from mocks.mock_responses import mock_responses  # noqa E402 W0611


@pytest.fixture
def mock_api():
    return API(url="http://example.local")


@pytest.fixture
def mock_vat_api():
    return VatAPI(url="http://vat-local.example")


@dataclass
class MockApiSubclass(API):
    @request_error_handler
    def mock_wrapped_func(self, mock_response):
        self.response = mock_response(self.url)
        self.response.raise_for_status()


@mock.patch.dict(
    os.environ,
    {
        "CI_PROJECT_NAME": "example/example/example",
        "CI_PROJECT_URL": "https://example/example/example",
    },
)
def test_request_error_decorator(caplog, mock_responses):  # noqa W0404
    caplog.set_level(logging.INFO)

    logging.info("It shouldn't throw exception on 200")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["200"])
    assert api.response.text == "successful_request"
    assert api.response.status_code == 200
    for record in caplog.records:
        assert record.levelname != "WARNING"
    caplog.clear()

    logging.info("It should handle exception on 400")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["400"])
    assert api.response.text == "bad_json_body"
    assert api.response.status_code == 400
    assert "Bad request" in caplog.text
    assert "bad_json_body" in caplog.text
    caplog.clear()

    logging.info("It should handle exception on 403")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["403"])
    assert api.response.text == "bad_auth"
    assert api.response.status_code == 403
    assert "is not authorized to use the image name of:" in caplog.text
    caplog.clear()

    logging.info("It should handle exception on 500")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["500"])
    assert api.response.text == "server_ded"
    assert api.response.status_code == 500
    assert "Unknown response from VAT" in caplog.text
    caplog.clear()

    logging.info("It should handle request exception")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["requestException"])
    assert api.response is None
    assert "Could not access VAT" in caplog.text
    caplog.clear()

    logging.info("It should handle runtime error")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["runtimeError"])
    assert api.response is None
    assert "Unexpected exception" in caplog.text
    caplog.clear()


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
