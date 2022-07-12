#!/usr/bin/env python3

import sys
import asyncio


from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.utils import logger
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.file_parser import DockerfileParser
from ironbank.pipeline.utils.exceptions import DockerfileParseError

log = logger.setup(name="lint.dockerfile_validation")


async def main():
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    log.debug("Validating dockerfile contents")
    try:
        if hardening_manifest.base_image_name or hardening_manifest.base_image_tag:
            invalid_from = DockerfileParser.parse("Dockerfile")
            if invalid_from:
                log.error(
                    "The final FROM statement in the Dockerfile must be FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}"
                )
                sys.exit(100)
    except DockerfileParseError:
        log.info("Failed to validate dockerfile")
        sys.exit(1)
    except Exception as e:
        log.info(f"Unexpected exception occurred. {e.__class__}")
        sys.exit(1)

    log.info("Dockerfile is validated.")


if __name__ == "__main__":
    asyncio.run(main())
