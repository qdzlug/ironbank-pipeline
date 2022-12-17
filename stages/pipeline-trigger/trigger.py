#!/usr/bin/env python3

import os
from ironbank.pipeline.utils import logger
from ironbank.pipeline.hardening_manifest import (
    get_source_keys_values,
)

log = logger.setup("pipeline_trigger")

artifact_storage = os.environ["ARTIFACT_STORAGE"]
label_dict = get_source_keys_values(f"{artifact_storage}/lint/labels.env")
log.info("OS_TYPE: %s", label_dict["mil.dso.ironbank.os-type"])
