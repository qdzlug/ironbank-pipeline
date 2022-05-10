import pytest
import logging
import sys
import os
from unittest import mock

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import logger

# This doesn't work without `from utils import logger` inside the test
# After this test successfully passes, `assert log.level == logging.INFO` fails below even after unsetting the env var and reimporting logger
# TODO: Get this test working with the tests below
# @mock.patch.dict(os.environ, {"LOGLEVEL": "DEBUG"})
# def test_setup_env_vars():
#     from utils import logger
#     logging.info("It should use env var to set level")
#     log = logger.setup('example')
#     assert log.level == logging.DEBUG


def test_setup():
    logging.info("It should setup logger without any handlers")
    log = logger.setup("example")
    assert log.level == logging.INFO
    assert not log.handlers

    logging.info("It should setup a logger with a FileHandler")
    log = logger.setup(
        name="example",
        level=logging.ERROR,
        format="%(message)s",
        debug_file="example.log",
    )
    assert log.level == logging.ERROR
    assert log.handlers[0].level == logging.DEBUG
    assert type(log.handlers[0]) == logging.FileHandler
