from dataclasses import dataclass
import requests
import pytest


@dataclass
class MockResponse:
    status_code: int
    text: str
    content: str = "example"

    def __enter__(self):
        return self

    def __exit__(self, mock1, mock2, mock3):
        pass

    def raise_for_status(self):
        if self.status_code != 200:
            raise requests.exceptions.HTTPError

    def json(self):
        return {"status_code": self.status_code, "text": self.text}


@dataclass
class MockInvalidJson(MockResponse):
    def json(self):
        raise requests.JSONDecodeError


@dataclass
class MockAnchoreResponse:
    returncode: int
    text: str
    content: str = "example"
    stderr: str = "canned_error"
    stdout: str = "It broke"


@pytest.fixture(scope="module")
def mock_responses():
    def mock200(*args, **kwargs):
        return MockResponse(200, "successful_request")

    def mock400(*args, **kwargs):
        return MockResponse(400, "bad_json_body")

    def mock403(*args, **kwargs):
        return MockResponse(403, "bad_auth")

    def mock404(*args, **kwargs):
        return MockResponse(404, "not_found")

    def mock500(*args, **kwargs):
        return MockResponse(500, "server_ded")

    def mock0(*args, **kwargs):
        return MockAnchoreResponse(0, "successful")

    def mock1(*args, **kwargs):
        return MockAnchoreResponse(1, "exists")

    def mock2(*args, **kwargs):
        return MockAnchoreResponse(2, "other_error")

    def mockRequestException(*args, **kwargs):
        raise requests.exceptions.RequestException

    def mockRuntimeError(*args, **kwargs):
        raise RuntimeError

    def mockJsonDecodeError(*args, **kwargs):
        return MockInvalidJson(200, "")

    return {
        "200": mock200,
        "400": mock400,
        "403": mock403,
        "404": mock404,
        "500": mock500,
        "0": mock0,
        "1": mock1,
        "2": mock2,
        "requestException": mockRequestException,
        "runtimeError": mockRuntimeError,
        "jsonDecodeError": mockJsonDecodeError,
    }
