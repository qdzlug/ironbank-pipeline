#!/usr/bin/env python3

import logging
import os
import sys


# Disabling redefined-builtin because the native logging also violates this
# pylint: disable=redefined-builtin
def setup(name="main", level=None, format=None, debug_file=None):
    """Setup a logger with the given parameters. If parameters are not
    provided, it will use environment variables or defaults.

    Args:
        name (str, optional): The name of the logger. Defaults to "main".
        level (str, optional): The level of logging. Defaults to environment variable "LOGLEVEL"
            if set, otherwise to "INFO".
        format (str, optional): The format of the logging messages. If not provided,
            a default format will be used based on the level.
        debug_file (str, optional): A file to which debug level logs should be written.
            If not provided, debug logs are not written to a file.

    Returns:
        Logger: A configured logger.
    """
    level = level if level else os.environ.get("LOGLEVEL", "INFO").upper()
    default_format = (
        "| %(levelname)s | [%(filename)s: %(lineno)d]: | %(message)s"
        if level == "DEBUG"
        else "| %(name)-28s | %(levelname)-8s | %(message)s"
    )
    # if format is truthy, use format
    # else if falsy, use default format
    format = format or default_format
    logging.basicConfig(level=level, stream=sys.stdout, format=format)
    logger = logging.getLogger(name)
    logger.setLevel(level)
    if debug_file:
        formatter = logging.Formatter(format)
        file_handler = logging.FileHandler(debug_file)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    return logger
