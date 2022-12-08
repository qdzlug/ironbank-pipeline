#!/usr/bin/env python3

import sys
import json
import jsonschema
import multiprocessing

from pathlib import Path
from ironbank.pipeline.utils import logger

# Keeping global until other methods get pulled into class in this file
log = logger.setup(name="renovate_json")


# Not using dataclass because post_init is required for file load and parameter initialization
class RenovateJson:
    def __init__(self, renovate_path: str, schema_path: str = "./", validate: bool = False):
        self.renovate_path: Path = Path(renovate_path)
        self.schema_path: Path = Path(schema_path)
        if validate:
            self.validate()

    def validate(self):
        self.validate_schema()
        log.info("Checking renovate.json schema")

    def validate_schema(self, conn: multiprocessing.Pipe) -> None:
        log.info("Validating schema")
        with self.renovate_path.open("r") as f:
            renovate_content = json.load(f)
        with self.schema_path.open("r") as f:
            schema_content = json.load(f)
        try:
            # may hang from catastrophic backtracking if format is invalid
            log.info("This task will exit if not completed within 2 minutes")
            jsonschema.Draft201909Validator(schema_content).validate(renovate_content)
        except jsonschema.ValidationError as ex:
            conn.send(ex.message)
            sys.exit(100)