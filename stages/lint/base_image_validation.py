#!/usr/bin/env python3

import os
import json
import asyncio
import pathlib

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.utils import logger
from ironbank.pipeline.container_tools.skopeo import Skopeo

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
        log.info("Inspect base image")
        base_img_inspect = Skopeo.inspect(manifest.base_image_name, manifest.base_image_tag)

        base_image_info = {"BASE_SHA": base_img_inspect['Digest'].strip().replace("'", "")}
        log.info("Dump SHA to file")
        with pathlib.Path(os.environ["ARTIFACT_DIR"], "base_image.json").open("w") as f:
            json.dump(base_image_info, f)
if __name__ == "__main__":
    asyncio.run(main())
