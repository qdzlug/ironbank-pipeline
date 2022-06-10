from dataclasses import dataclass
import requests
import pytest


@dataclass
class MockResponse:
    status_code: int
    text: str

    def raise_for_status(self):
        if self.status_code != 200:
            raise requests.exceptions.HTTPError

    def json(self):
        return {"status_code": self.status_code, "text": self.text}


@pytest.fixture(scope="module")
def mock_responses(url="", params={}, headers={}):
    def mock200(url="", params={}, headers={}):
        return MockResponse(200, "successful_request")

    def mock400(url="", params={}, headers={}):
        return MockResponse(400, "bad_json_body")

    def mock403(url="", params={}, headers={}):
        return MockResponse(403, "bad_auth")

    def mock404(url="", params={}, headers={}):
        return MockResponse(404, "not_found")

    def mock500(url="", params={}, headers={}):
        return MockResponse(500, "server_ded")

    def mockRequestException(url="", params={}, headers={}):
        raise requests.exceptions.RequestException

    def mockRuntimeError(url="", params={}, headers={}):
        raise RuntimeError

    return {
        "200": mock200,
        "400": mock400,
        "403": mock403,
        "404": mock404,
        "500": mock500,
        "requestException": mockRequestException,
        "runtimeError": mockRuntimeError,
    }
