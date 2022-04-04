#!/usr/bin/env python3

import logging
import os

LOG_LEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
LOG_FORMAT = (
    "%(levelname)s [%(filename)s:%(lineno)d]: %(message)s"
    if LOG_LEVEL == "DEBUG"
    else "%(levelname)s: %(message)s"
)


def setup(name="main", level=LOG_LEVEL, format=LOG_FORMAT, debug_file=None):
    logger = logging.getLogger(name)
    logger.setLevel(level)
    streamHandler = logging.StreamHandler()
    logger.addHandler(streamHandler)
    if debug_file is not None:
        formatter = logging.Formatter(format)
        fileHandler = logging.FileHandler(debug_file)
        fileHandler.setLevel(logging.DEBUG)
        fileHandler.setFormatter(formatter)
        logger.addHandler(fileHandler)
    return logger
