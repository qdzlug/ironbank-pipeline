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
