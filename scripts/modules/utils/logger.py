#!/usr/bin/env python3

import logging
import os
import sys

LOG_LEVEL = os.environ.get("LOGLEVEL", "INFO").upper()
LOG_FORMAT = (
    "| %(levelname)s | [%(filename)s: %(lineno)d]: | %(message)s"
    if LOG_LEVEL == "DEBUG"
    else "| %(name)-28s | %(levelname)-8s | %(message)s"
)


def setup(name="main", level=LOG_LEVEL, format=LOG_FORMAT, debug_file=None):
    logging.basicConfig(level=level, stream=sys.stdout, format=format)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if debug_file:
        formatter = logging.Formatter(format)
        fileHandler = logging.FileHandler(debug_file)
        fileHandler.setLevel(logging.DEBUG)
        fileHandler.setFormatter(formatter)
        logger.addHandler(fileHandler)
    return logger
