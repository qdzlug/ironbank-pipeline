#!/usr/bin/env python3

import asyncio
import sys

import base_image_validation
import dockerfile_validation
import folder_structure
import hardening_manifest_validation
import pipeline_auth_status

from ironbank.pipeline.utils import logger  # noqa E402
from ironbank.pipeline.utils.exceptions import SymlinkFoundError

log = logger.setup("lint_jobs")

system_exits: dict = {}


# Proper planning prevents painfully poor performance
def handle_system_exit(func):
    async def _handle_system_exit(*args, **kwargs):
        try:
            return await func()
        except SystemExit as e:
            system_exits[e.code] = (
                system_exits[e.code] if system_exits.get(se.code) else []
            )
            system_exits[se.code].append(func.__module__)
        except SymlinkFoundError as e:
            log.error(e)
            sys.exit(1)

    return _handle_system_exit


async def main():
    HARD_FAIL_CODE = 1
    SOFT_FAIL_CODE = 100

    await handle_system_exit(folder_structure.main)()
    await handle_system_exit(hardening_manifest_validation.main)()
    await handle_system_exit(dockerfile_validation.main)()
    await handle_system_exit(base_image_validation.main)()
    if HARD_FAIL_CODE not in system_exits.keys():
        await handle_system_exit(pipeline_auth_status.main)()
    else:
        log.warning("Skipping pipeline auth status due to prior failure")

    for error_code, stages in system_exits.items():
        log.error(f"The following stages returned error code: {error_code}")
        for stage in stages:
            log.error(f"\t- {stage}")

    if HARD_FAIL_CODE in system_exits:
        log.error("Failing pipeline")
        sys.exit(HARD_FAIL_CODE)
    elif SOFT_FAIL_CODE in system_exits:
        log.warning("Failing pipeline")
        sys.exit(SOFT_FAIL_CODE)
    else:
        log.info("All stages successful")


if __name__ == "__main__":
    asyncio.run(main())
