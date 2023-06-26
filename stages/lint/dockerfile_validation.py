#!/usr/bin/env python3

import asyncio
import re
import subprocess
import sys

from ironbank.pipeline.file_parser import DockerfileParser
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.decorators import subprocess_error_handler

log = logger.setup(name="lint.dockerfile_validation")


async def main():
    """Asynchronous main function that validates the Dockerfile of a DSOP (Data
    Standard for Operational Parameters) project against a hardening manifest.

    The function performs the following steps:
    1. Initializes a DsopProject and a HardeningManifest object using the hardening_manifest_path from the DsopProject.
    2. Executes the Hadolint Dockerfile linter on the Dockerfile, capturing the output. If Hadolint fails to run, it logs an error message.
    3. Parses and logs the output from Hadolint. If the output doesn't match the expected format, it logs a warning and exits with status 1.
    4. If the hardening manifest specifies a base image name or tag, it checks that the final FROM statement in the Dockerfile matches
       the format "FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}". If it doesn't, an error is logged and the program exits with status 100.
    5. Logs a message indicating that the Dockerfile has been successfully validated.

    Note:
    The function is designed to run in an asynchronous context and should be invoked using asyncio.run().

    Raises:
    SystemExit: The function exits with status 1 if the output from Hadolint can't be parsed, and with status 100 if the Dockerfile's final
                FROM statement doesn't match the expected format.

    Todo:
    Consider moving the subprocess_error_handler decorator to the main function if/when the async designation is removed from this function.
    """
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    log.debug("Validating dockerfile contents")
    # TODO: move this decorator to main when/if we remove the async from the main func
    result = subprocess_error_handler(logging_message="Running hadolint failed")(
        subprocess.run
    )(
        ["hadolint", "Dockerfile", "--no-fail"],
        check=True,
        capture_output=True,
        text=True,
    )
    hadolint_results = result.stdout or "No hadolint findings found\n"
    log.info("")
    log.info("Hadolint results:")
    for hl_result in hadolint_results.split("\n"):
        log.info(hl_result)
    if not re.match(r"^Dockerfile(:[0-9]+)+ (DL|SC)", result.stdout) and result.stdout:
        log.warning("Unable to parse dockerfile")
        sys.exit(1)
    if hardening_manifest.base_image_name or hardening_manifest.base_image_tag:
        invalid_from = DockerfileParser.parse("Dockerfile")
        if invalid_from:
            log.error(
                "The final FROM statement in the Dockerfile must be FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}"
            )
            sys.exit(100)

    log.info("Dockerfile is validated.")


if __name__ == "__main__":
    asyncio.run(main())
