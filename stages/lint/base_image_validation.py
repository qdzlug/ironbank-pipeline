#!/usr/bin/env python3

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.image import Image
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.exceptions import GenericSubprocessError

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

        if os.environ.get("STAGING_BASE_IMAGE"):
            # Grab staging pull docker auth
            pull_auth = Path(os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"])
            registry = os.environ["REGISTRY_PRE_PUBLISH_URL"]
        else:
            # Grab prod docker auth
            pull_auth = Path(os.environ["DOCKER_AUTH_FILE_PULL"])
            registry = os.environ["BASE_REGISTRY"]

        try:
            skopeo = Skopeo(authfile=pull_auth)
            base_image = Image(
                registry=registry,
                name=manifest.base_image_name,
                tag=manifest.base_image_tag,
                transport="docker://",
            )
            base_img_inspect = skopeo.inspect(base_image, log_cmd=True)
        except GenericSubprocessError:
            log.error(
                "Failed to inspect IMAGE:TAG provided in hardening_manifest. \
                    Please validate this image exists in the registry1.dso.mil/ironbank project."
            )
            log.error(f"Failed 'skopeo inspect' of image: {base_image}")
            sys.exit(1)
        with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:
            log.info("Verifying base image signature")
            shutil.copy(
                pull_auth,
                Path(docker_config_dir, "config.json"),
            )
            if not Cosign.verify(
                image=base_image.from_image(transport=""),
                docker_config_dir=docker_config_dir,
                use_key=True,
                log_cmd=True,
            ):
                log.error("Failed to verify base image signature")
                sys.exit(1)

        base_image_info = {"BASE_SHA": base_img_inspect["Digest"]}
        log.info("Dump SHA to file")
        with Path(os.environ["ARTIFACT_DIR"], "base_image.json").open("w") as f:
            json.dump(base_image_info, f)


if __name__ == "__main__":
    asyncio.run(main())
