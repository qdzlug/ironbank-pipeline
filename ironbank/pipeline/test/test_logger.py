import logging
import os
from unittest import mock

from ironbank.pipeline.utils import logger  # noqa E402


@mock.patch.dict(os.environ, {"LOGLEVEL": "DEBUG"})
def test_setup_env_vars():
    logging.info("It should use env var to set level")
    log = logger.setup("example")
    assert log.level == logging.DEBUG


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
    assert isinstance(log.handlers[0], logging.FileHandler)
