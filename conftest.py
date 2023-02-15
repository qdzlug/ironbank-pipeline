import pytest
import requests
from dataclasses import dataclass
from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import MockResponse


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
    
    def mock200_with_x_total_count_headers(*args, **kwargs):
        return MockResponse(status_code=200, text="successful_request",headers={"x-total-count":"test"})

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
        "200_with_x_total_count_headers": mock200_with_x_total_count_headers,
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


@pytest.fixture(scope="module")
def mock_decorator():
    decorator_log = logger.setup("mock_decorator")

    def mocked_decorator_simple(func):
        def wrapper(*args, **kwargs):
            decorator_log.info(f"Decorator called for {func.__name__}")
            return func(*args, **kwargs)

    def mocked_decorator_with_arg(decorator_arg=""):
        decorator_log.info(f"Args passed to decorator {decorator_arg}")
        return mocked_decorator_simple

    return {"simple": mocked_decorator_simple, "with_arg": mocked_decorator_with_arg}
