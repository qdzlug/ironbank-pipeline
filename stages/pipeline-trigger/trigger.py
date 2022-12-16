#!/usr/bin/env python3

import os
from ironbank.pipeline.utils import logger

log = logger.setup("pipeline_trigger")

log.info(os.environ["mil.dso.ironbank.os-type"])
