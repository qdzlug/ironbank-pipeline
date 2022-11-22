from ironbank.pipeline.utils.types import FileParser
from ironbank.pipeline.utils import logger
from ironbank.pipeline.test.mocks.mock_classes import (
    MockPath,
)
import pytest
from unittest.mock import patch

log = logger.setup("test_types")


@pytest.mark.only
@patch("ironbank.pipeline.utils.types.Path", new=MockPath)
def test_handle_file_obj(monkeypatch, caplog):
    log.info("Test same obj returned if not Path")
    test_str = "a"
    ret_val = FileParser.handle_file_obj(test_str)
    assert test_str == ret_val

    log.info("Test exception thrown if Path doesn't exist")
    ret_val = None
    monkeypatch.setattr(MockPath, "exists", lambda self: False)
    with pytest.raises(FileNotFoundError):
        ret_val = FileParser.handle_file_obj(MockPath("a"))
    assert ret_val is None

    log.info("Test successful json load")
    # monkeypatch.setattr(json, "loads", lambda x: x)
    # monkeypatch.setattr("MockPath", "exists", True)
    # monkeypatch.setattr(MockPath, "exists", lambda self: True)
    # monkeypatch.setattr(
    #     MockOpen,
    #     "__enter__",
    #     lambda x: ["test"],
    # )
    # monkeypatch.setattr(pathlib.Path, "exists", lambda self: True)
    # ret_val = FileParser.handle_file_obj(MockPath("a.json"))

    log.info("Test successful readlines")
