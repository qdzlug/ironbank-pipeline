import os
import sys
import pytest
import logging
from dataclasses import dataclass
from subprocess import CalledProcessError
from unittest import mock

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from apis import API  # noqa E402
from utils import logger  # noqa E402
from utils.decorators import request_retry  # noqa E402
from utils.decorators import request_error_handler  # noqa E402
from mocks.mock_responses import mock_responses  # noqa E402 W0611

log = logger.setup("test_decorators")


@dataclass
class MockClass:
    log: logger = logger.setup("MockClass")

    @request_retry(3)
    def mock_func(self):
        pass

    @request_retry(3)
    def mock_failing_func(self):
        raise CalledProcessError(1, ["example"])


@pytest.fixture
def mock_class():
    return MockClass()


@dataclass
class MockApiSubclass(API):
    @request_error_handler
    def mock_wrapped_func(self, mock_response):
        self.response = mock_response(self.url)
        self.response.raise_for_status()


def test_request_retry(caplog, mock_class):
    mock_class.mock_func()
    with pytest.raises(CalledProcessError):
        mock_class.mock_failing_func()


@mock.patch.dict(
    os.environ,
    {
        "CI_PROJECT_NAME": "example/example/example",
        "CI_PROJECT_URL": "https://example/example/example",
    },
)
def test_request_error_decorator(caplog, mock_responses):  # noqa W0404
    caplog.set_level(logging.INFO)

    log.info("It shouldn't throw exception on 200")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["200"])
    assert api.response.text == "successful_request"
    assert api.response.status_code == 200
    for record in caplog.records:
        assert record.levelname != "WARNING"
    caplog.clear()

    log.info("It should handle exception on 400")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["400"])
    assert api.response.text == "bad_json_body"
    assert api.response.status_code == 400
    assert "Bad request" in caplog.text
    assert "bad_json_body" in caplog.text
    caplog.clear()

    log.info("It should handle exception on 403")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["403"])
    assert api.response.text == "bad_auth"
    assert api.response.status_code == 403
    assert "is not authorized to use the image name of:" in caplog.text
    caplog.clear()

    log.info("It should handle exception on 500")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["500"])
    assert api.response.text == "server_ded"
    assert api.response.status_code == 500
    assert "Unknown response from VAT" in caplog.text
    caplog.clear()

    log.info("It should handle request exception")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["requestException"])
    assert api.response is None
    assert "Could not access VAT" in caplog.text
    caplog.clear()

    log.info("It should handle runtime error")
    api = MockApiSubclass(url="https://example.local")
    api.mock_wrapped_func(mock_responses["runtimeError"])
    assert api.response is None
    assert "Unexpected exception" in caplog.text
    caplog.clear()
