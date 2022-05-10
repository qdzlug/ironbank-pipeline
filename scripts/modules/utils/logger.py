#!/usr/bin/env python3

import logging
import os
import sys


def setup(name="main", level=None, format=None, debug_file=None):
    level = level if level else os.environ.get("LOGLEVEL", "INFO").upper()
    default_format = (
        "| %(levelname)s | [%(filename)s: %(lineno)d]: | %(message)s"
        if level == "DEBUG"
        else "| %(name)-28s | %(levelname)-8s | %(message)s"
    )
    format = format if format else default_format
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
