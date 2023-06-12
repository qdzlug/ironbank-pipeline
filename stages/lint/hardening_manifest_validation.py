#!/usr/bin/env python3

import asyncio
import sys
from pathlib import Path

from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.utils import logger

log = logger.setup(name="lint.metadata")


async def main():
    """
    This script is used to validate the hardening manifest of a DSOP project.

    It initializes a DSOP project and a hardening manifest. The hardening manifest is then validated, and any artifacts 
    it requires are created. The script will log an error and exit with a status code of 1 if there are invalid labels, 
    maintainers, or partner advocates in the hardening manifest. If the hardening manifest contains invalid image sources,
    a warning is logged, and the script exits with a status code of 100. If there are no issues, the script will log that
    the hardening manifest is validated.

    It is meant to be run as a standalone script and can be executed with any Python 3.7+ interpreter.
    """
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(
        dsop_project.hardening_manifest_path,
        Path(
            Path(__file__).parent.parent.parent, "schema/hardening_manifest.schema.json"
        ).as_posix(),
        validate=True,
    )
    hardening_manifest.create_artifacts()
    if (
        hardening_manifest.invalid_labels
        or hardening_manifest.invalid_maintainers
        or hardening_manifest.invalid_partner_advocates
    ):
        log.error(
            "Please update these labels to appropriately describe your container before rerunning this pipeline"
        )
        sys.exit(1)
    elif hardening_manifest.invalid_image_sources:
        log.warning(
            "Please update these tags to ensure they do not contain registry1.dso.mil"
        )
        sys.exit(100)
    log.info("Hardening manifest is validated")


if __name__ == "__main__":
    asyncio.run(main())
