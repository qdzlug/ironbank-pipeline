#!/usr/bin/env python3

import logging
import sys

DEFAULT_FORMAT = "%(name)-12s  %(levelname)-8s %(message)s"

logging.basicConfig(level=logging.INFO, stream=sys.stdout, format=DEFAULT_FORMAT)


def setup(name="main", level=logging.INFO, format=DEFAULT_FORMAT, debug_file=None):
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
