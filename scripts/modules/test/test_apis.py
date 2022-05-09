import os
import sys
import logging
from unittest import mock
import pytest
import requests

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from apis import *
from utils import logger


@pytest.fixture
def mock_api():
    return API(url="http://example.local")


@pytest.fixture
def mock_vat_api():
    return VatAPI(url="http://vat-local.example")


@dataclass
class MockSessionResponse:
    status_code: int
    text: str


# Various responses for a mocked request object (200, 400, 403, 500)
@pytest.fixture
def mock_responses(monkeypatch):
    def mock200(url=""):
        return MockSessionResponse(200, "successful_request")

    def mock400(url=""):
        return MockSessionResponse(400, "bad_json_body")

    def mock403(url=""):
        return MockSessionResponse(403, "bad_auth")

    def mock500(url=""):
        return MockSessionResponse(500, "server_ded")

    def mockRequestException(url=""):
        raise requests.exceptions.RequestException

    def mockRuntimeError(url=""):
        raise RuntimeError

    session200 = requests.session()
    session400 = requests.session()
    session403 = requests.session()
    session500 = requests.session()
    sessionReqEx = requests.session()
    sessionRunErr = requests.session()
    monkeypatch.setattr(session200, "get", mock200)
    monkeypatch.setattr(session200, "put", mock200)
    monkeypatch.setattr(session200, "post", mock200)
    monkeypatch.setattr(session400, "get", mock400)
    monkeypatch.setattr(session400, "put", mock400)
    monkeypatch.setattr(session400, "post", mock400)
    monkeypatch.setattr(session403, "get", mock403)
    monkeypatch.setattr(session403, "put", mock403)
    monkeypatch.setattr(session403, "post", mock403)
    monkeypatch.setattr(session500, "get", mock500)
    monkeypatch.setattr(session500, "put", mock500)
    monkeypatch.setattr(session500, "post", mock500)
    monkeypatch.setattr(sessionReqEx, "get", mockRequestException)
    monkeypatch.setattr(sessionReqEx, "put", mockRequestException)
    monkeypatch.setattr(sessionReqEx, "post", mockRequestException)
    monkeypatch.setattr(sessionRunErr, "get", mockRuntimeError)
    monkeypatch.setattr(sessionRunErr, "put", mockRuntimeError)
    monkeypatch.setattr(sessionRunErr, "post", mockRuntimeError)
    return {
        "200": session200,
        "400": session400,
        "403": session403,
        "500": session500,
        "requestErr": sessionReqEx,
        "runErr": sessionRunErr,
    }


class MockRequest:
    def __init__(self, session):
        self.image_name = "example/example/example"
        self.url = "https://example/example.invalid"
        self.session = session
        self.response = None
        self.log = logger.setup("mock_request_log")

    def raise_for_status(self):
        if self.response.status_code != 200:
            raise requests.exceptions.HTTPError

    @request_error_handler
    def mock_func(self, image_name="example/example/example"):
        self.response = self.session.get(url="https://invalid.invalid")
        self.raise_for_status()


@mock.patch.dict(
    os.environ,
    {
        "CI_PROJECT_NAME": "example/example/example",
        "CI_PROJECT_URL": "https://example/example/example",
    },
)
def test_request_error_handler(caplog, mock_responses):
    caplog.set_level(logging.INFO)

    logging.info("It shouldn't throw exception on 200")
    mock_request = MockRequest(mock_responses["200"])
    response = mock_request.mock_func()
    assert mock_request.response.text == "successful_request"
    assert mock_request.response.status_code == 200
    for record in caplog.records:
        assert record.levelname != "WARNING"
    caplog.clear()

    # TODO: test thrown excpetion is caught
    logging.info("It should throw exception on 400")
    mock_request = MockRequest(mock_responses["400"])
    mock_request.mock_func()
    assert mock_request.response.text == "bad_json_body"
    assert mock_request.response.status_code == 400
    assert "Bad request" in caplog.text
    assert "bad_json_body" in caplog.text
    caplog.clear()

    mock_request = MockRequest(mock_responses["403"])
    mock_request.mock_func()
    assert mock_request.response.text == "bad_auth"
    assert mock_request.response.status_code == 403
    assert "is not authorized to use the image name of:" in caplog.text
    caplog.clear()

    mock_request = MockRequest(mock_responses["500"])
    mock_request.mock_func()
    assert mock_request.response.text == "server_ded"
    assert mock_request.response.status_code == 500
    assert "Unknown response from VAT" in caplog.text
    caplog.clear()

    mock_request = MockRequest(mock_responses["requestErr"])
    mock_request.mock_func()
    assert mock_request.response == None
    assert "Could not access VAT" in caplog.text
    caplog.clear()

    mock_request = MockRequest(mock_responses["runErr"])
    mock_request.mock_func()
    assert mock_request.response == None
    assert "Unexpected exception" in caplog.text
    caplog.clear()
