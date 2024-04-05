#!/usr/bin/env python3

import asyncio
import sys

from pipeline.project import DsopProject
from common.utils import logger

log = logger.setup("lint.folder_structure")


def main():
    """Validates the folder structure of a DsopProject.

    Initializes a DsopProject object and attempts to validate it. If
    validation fails (i.e., an AssertionError is raised), logs the error
    and terminates the program with status 1.
    """
    log.info("Validating folder structure")
    dsop_project = DsopProject()

    try:
        dsop_project.validate()
        log.info("Folder structure validated")
    except AssertionError as e:
        log.error(f"Assertion Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    print("This should only be called from lint_jobs.py")
