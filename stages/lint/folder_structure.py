#!/usr/bin/env python3

import sys
import asyncio

from ironbank.pipeline.utils import logger
from ironbank.pipeline.project import DsopProject

log = logger.setup("lint.folder_structure")


async def main():
    log.info("Validating folder structure")
    dsop_project = DsopProject()

    try:
        dsop_project.validate()
        log.info("Folder structure validated")
    except AssertionError as ae:
        log.error(f"Assertion Error: {ae}")
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
