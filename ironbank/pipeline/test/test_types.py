import json
from unittest.mock import patch

import pytest

from ironbank.pipeline.test.mocks.mock_classes import MockPath
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.types import FileParser

log = logger.setup("test_types")


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
    monkeypatch.setattr(MockPath, "exists", lambda self: True)
    monkeypatch.setattr(json, "load", lambda x: x)
    ret_val = FileParser.handle_file_obj(MockPath("a.json"))

    log.info("Test successful readlines")
    ret_val = FileParser.handle_file_obj(MockPath("a"))
