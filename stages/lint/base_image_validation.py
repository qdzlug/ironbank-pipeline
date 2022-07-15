#!/usr/bin/env python3

import asyncio

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.utils import logger
import ironbank.pipeline.base_image as base

log = logger.setup(name="lint.base_image_validation")


async def main():
    #
    # Hardening manifest is expected for all of the current repos that are being processed.
    # At the very least the hardening_manifest.yaml should be generated if it has not been
    # merged in yet.
    #
    dsop_project = DsopProject()
    manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    if manifest.base_image_name:
        base.skopeo_inspect_base_image(manifest.base_image_name, manifest.base_image_tag)


if __name__ == "__main__":
    asyncio.run(main())
