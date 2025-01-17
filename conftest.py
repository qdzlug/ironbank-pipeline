from dataclasses import dataclass

import pytest
import requests

from pipeline.test.mocks.mock_classes import MockCompletedProcess, MockResponse
from common.utils import logger


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
        return MockResponse(
            status_code=200, text="successful_request", headers={"x-total-count": 1}
        )

    def mock200_with_x_total_count_headers_and_pages(*args, **kwargs):
        return MockResponse(
            status_code=200,
            text="successful_request",
            headers={"x-total-count": 1},
            content={"page": "page", "page_size": 1, "q": "q"},
        )

    def mock400(*args, **kwargs):
        return MockResponse(status_code=400, text="bad_json_body")

    def mock403(*args, **kwargs):
        return MockResponse(status_code=403, text="bad_auth")

    def mock404(*args, **kwargs):
        return MockResponse(status_code=404, text="not_found")

    def mock500(*args, **kwargs):
        return MockResponse(status_code=500, text="server_ded")

    def mockRequestException(*args, **kwargs):
        raise requests.exceptions.RequestException

    def mockRuntimeError(*args, **kwargs):
        raise RuntimeError

    def mockJsonDecodeError(*args, **kwargs):
        return MockInvalidJson(status_code=200, text="")

    return {
        "200": mock200,
        "200_with_x_total_count_headers": mock200_with_x_total_count_headers,
        "mock200_with_x_total_count_headers_and_pages": mock200_with_x_total_count_headers_and_pages,
        "400": mock400,
        "403": mock403,
        "404": mock404,
        "500": mock500,
        "requestException": mockRequestException,
        "runtimeError": mockRuntimeError,
        "jsonDecodeError": mockJsonDecodeError,
    }


@pytest.fixture(scope="module")
def mock_completed_process():
    def mock0(*args, **kwargs):
        return MockCompletedProcess(returncode=0, text="successful")

    def mock1(*args, **kwargs):
        return MockCompletedProcess(returncode=1, text="exists")

    def mock2(*args, **kwargs):
        return MockCompletedProcess(returncode=2, text="other_error")

    return {
        "0": mock0,
        "1": mock1,
        "2": mock2,
    }


@pytest.fixture
def raise_():
    """
    Helper function allowing for a lambda to raise an exception
    """

    def raise_exception(e):
        raise e

    return raise_exception


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
