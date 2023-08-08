"""This creates a logger according to the Singleton pattern."""

import logging
from common.utils import logger

log: logging.Logger = logger.setup("OpenSCAP")

# TODO: why does this docstring suck?
