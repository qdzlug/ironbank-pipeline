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
    """This function is a decorator used to handle and log system exits for the
    given function. It also handles SymlinkFoundError, logs it and exits with
    code 1.

    :param func: Function that needs to be wrapped
    :return: Wrapped function that can handle SystemExit
    """

    async def _handle_system_exit(*args, **kwargs):  # pylint: disable=W0613
        try:
            return await func()
        except SystemExit as e:
            system_exits[e.code] = (
                system_exits[e.code] if system_exits.get(e.code) else []
            )
            system_exits[e.code].append(func.__module__)
        except SymlinkFoundError as e:
            log.error(e)
            sys.exit(1)

    return _handle_system_exit


async def main():
    """Main function for the script.

    Executes a series of functions which perform validations on
    different aspects of the pipeline (like folder structure,
    dockerfile, etc.) and handles exit codes. Depending on the exit
    codes, it determines whether to fail the pipeline or not, logging
    all relevant information in the process.
    """
    hard_fail_code = 1
    soft_fail_code = 100

    await handle_system_exit(folder_structure.main)()
    await handle_system_exit(hardening_manifest_validation.main)()
    await handle_system_exit(dockerfile_validation.main)()
    await handle_system_exit(base_image_validation.main)()
    if hard_fail_code not in system_exits:
        await handle_system_exit(pipeline_auth_status.main)()
    else:
        log.warning("Skipping pipeline auth status due to prior failure")

    for error_code, stages in system_exits.items():
        log.error(f"The following stages returned error code: {error_code}")
        for stage in stages:
            log.error(f"\t- {stage}")

    if hard_fail_code in system_exits:
        log.error("Failing pipeline")
        sys.exit(hard_fail_code)
    elif soft_fail_code in system_exits:
        log.warning("Failing pipeline")
        sys.exit(soft_fail_code)
    else:
        log.info("All stages successful")


if __name__ == "__main__":
    asyncio.run(main())
