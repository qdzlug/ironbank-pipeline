import pytest
import requests
from dataclasses import dataclass


@dataclass
class MockResponse:
    returncode: int = 1
    status_code: int = 500
    text: str = "example"
    content: str = "example"
    stderr: str = "canned_error"
    stdout: str = "It broke"

    def __enter__(self):
        return self

    def __exit__(self, mock1, mock2, mock3):
        pass

    def raise_for_status(self):
        if self.status_code != 200:
            raise requests.exceptions.HTTPError

    def iter_content(self, chunk_size=2048):
        return [b"abcdef", b"ghijkl", b"mnopqrs"]

    def json(self):
        return {"status_code": self.status_code, "text": self.text}


class MockJsonDecodeError(requests.JSONDecodeError):
    def __init__(self):
        pass


@dataclass
class MockInvalidJson(MockResponse):
    def json(self):
        raise MockJsonDecodeError()


@pytest.fixture(scope="module")
def mock_responses():
    def mock200(*args, **kwargs):
        return MockResponse(status_code=200, text="successful_request")

    def mock400(*args, **kwargs):
        return MockResponse(status_code=400, text="bad_json_body")

    def mock403(*args, **kwargs):
        return MockResponse(status_code=403, text="bad_auth")

    def mock404(*args, **kwargs):
        return MockResponse(status_code=404, text="not_found")

    def mock500(*args, **kwargs):
        return MockResponse(status_code=500, text="server_ded")

    def mock0(*args, **kwargs):
        return MockResponse(returncode=0, text="successful")

    def mock1(*args, **kwargs):
        return MockResponse(returncode=1, text="exists")

    def mock2(*args, **kwargs):
        return MockResponse(returncode=2, text="other_error")

    def mockRequestException(*args, **kwargs):
        raise requests.exceptions.RequestException

    def mockRuntimeError(*args, **kwargs):
        raise RuntimeError

    def mockJsonDecodeError(*args, **kwargs):
        return MockInvalidJson(status_code=200, text="")

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
