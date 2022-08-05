#!/usr/bin/env python3

from base64 import b64decode
import os
import json
import asyncio
import pathlib
import subprocess
import sys
import tempfile

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

        with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as tmp_dir:

            if os.environ.get("STAGING_BASE_IMAGE"):
                auth_file = pathlib.Path(tmp_dir, "staging_pull_auth.json")
                # Grab prod pull docker auth
                pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_STAGING"]).decode(
                    "UTF-8"
                )
                auth_file.write_text(pull_auth)
                registry = os.environ["REGISTRY_URL_STAGING"]
            else:
                auth_file = pathlib.Path(tmp_dir, "prod_pull_auth.json")
                # Grab staging docker auth
                pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode(
                    "UTF-8"
                )
                auth_file.write_text(pull_auth)
                registry = os.environ["REGISTRY_URL_PROD"]
            try:
                base_img_inspect = Skopeo.inspect(
                    f"{registry}/{manifest.base_image_name}:{manifest.base_image_tag}",
                    tmp_dir,
                )
            except subprocess.CalledProcessError as e:
                log.error(
                    "Failed to inspect IMAGE:TAG provided in hardening_manifest. \
                        Please validate this image exists in the registry1.dso.mil/ironbank project."
                )
                log.error(
                    f"Failed 'skopeo inspect' of image: {manifest.base_image_name}, {manifest.base_image_tag}"
                )
                log.error(f"Return code: {e.returncode}")
                sys.exit(1)

            base_image_info = {"BASE_SHA": base_img_inspect["Digest"]}
            log.info("Dump SHA to file")
            with pathlib.Path(os.environ["ARTIFACT_DIR"], "base_image.json").open(
                "w"
            ) as f:
                json.dump(base_image_info, f)


if __name__ == "__main__":
    asyncio.run(main())
