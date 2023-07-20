import logging
import os
import sys
from abc import ABC
from typing import Optional
from dataclasses import dataclass

# TODO: move this logger mixin


@dataclass
class LoggerMixin(ABC):
    """Mixin class to provide logging capabilities.

    This class provides a `_log` property which returns a logger instance
    configured with the name of the class.

    Examples
    --------
    To use this mixin, just inherit from it in your class definition:

    >>> class MyClass(LoggerMixin):
    ...     def my_method(self):
    ...         self._log.info('This is an info message')

    Then you can use the `_log` property like a typical logger.

    Attributes
    ----------
    _log : logging.Logger
        Logger instance with the name of the class.
    """

    @property
    def _log(self) -> logging.Logger:
        """Property to set up a logger with a class name.

        Returns
        -------
        logging.Logger
            The logger instance with class name as logger name.
        """
        if not hasattr(self, "_logger"):  # only initialize it once
            self._logger = setup(self.__class__.__name__)
        return self._logger


# Disabling redefined-builtin because the native logging also violates this
# pylint: disable=redefined-builtin
def setup(
    name: str = "main",
    level: Optional[str] = None,
    format: Optional[str] = None,
    debug_file: Optional[str] = None,
) -> logging.Logger:
    """Setup a logger with the given parameters.

    If parameters are not provided, it will use environment variables or defaults.

    Parameters
    ----------
    name : str, optional
        The name of the logger, by default "main"
    level : str, optional
        The level of logging, by default "INFO", it can be overridden by environment variable "LOGLEVEL"
    format : str, optional
        The format of the logging messages. If not provided, a default format will be used based on the level
    debug_file : str, optional
        A file to which debug level logs should be written. If not provided, debug logs are not written to a file

    Returns
    -------
    logging.Logger
        A configured logger.
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
