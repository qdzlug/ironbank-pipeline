#!/usr/bin/env python3

import asyncio
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
import urllib
import requests

from pipeline.container_tools.cosign import Cosign
from pipeline.container_tools.skopeo import Skopeo
from pipeline.hardening_manifest import HardeningManifest
from pipeline.image import Image
from pipeline.project import DsopProject
from pipeline.utils.exceptions import GenericSubprocessError
from pipeline.utils.decorators import stack_trace_handler
from common.utils import logger

log = logger.setup(name="lint.base_image_validation")


@stack_trace_handler
async def main(platform):
    """This script is designed to perform validation on a base image specified
    in a hardening manifest file.

    The validation process includes inspecting the base image and verifying its signature. If these checks pass,
    the script extracts the SHA of the base image and writes it to a JSON file.

    This script expects to find the Docker authentication files and relevant environment variables properly set in
    the running environment.

    Functions:
        main(): Performs the main functionality of the script. It creates a DsopProject object and a
                HardeningManifest object, inspects the base image specified in the hardening manifest,
                verifies the base image's signature, and writes the SHA of the base image to a JSON file.

    Usage:
        To run the script, navigate to its location and execute the command: python3 base_image_validation.py
    """
    #
    # Hardening manifest is expected for all of the current repos that are being processed.
    # At the very least the hardening_manifest.yaml should be generated if it has not been
    # merged in yet.
    #
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    if hardening_manifest.base_image_name:
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
            base_registry = os.environ["BASE_REGISTRY"]
            base_registry = base_registry.split("/")[0]
            with open(os.environ["DOCKER_AUTH_FILE_PULL"]) as f:
                auth = json.load(f)
            encoded_credentials = auth["auths"][base_registry]["auth"]
            headers = {
                "Accept": "application/json",
                "Authorization": f"Basic {encoded_credentials}",
            }
            encoded_image_name = urllib.parse.quote(
                hardening_manifest.base_image_name, safe=""
            )
            url = f"https://{base_registry}/api/v2.0/projects/ironbank/repositories/{encoded_image_name}/artifacts/{hardening_manifest.base_image_tag}"
            response = requests.get(url, headers=headers)
            response.raise_for_status()  # Raise an exception for 4xx or 5xx status codes
            json_data = response.json()
            skopeo = Skopeo(authfile=pull_auth)

            # If it's a manifest-list get platform sha.
            if (json_data["manifest_media_type"] == "application/vnd.oci.image.index.v1+json"):
                for image in json_data["references"]:
                    if image["platform"]["architecture"] == platform:
                        digest = image["child_digest"]
                base_image = Image(
                    registry=registry,
                    name=hardening_manifest.base_image_name,
                    digest=digest,
                    transport="docker://",
                )
            else:
                base_image = Image(
                    registry=registry,
                    name=hardening_manifest.base_image_name,
                    tag=hardening_manifest.base_image_tag,
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
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            exit(1)
        if not os.environ.get("STAGING_BASE_IMAGE"):
            with tempfile.TemporaryDirectory(
                prefix="DOCKER_CONFIG-"
            ) as docker_config_dir:
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
        platform_artifact_dir = Path(f"{os.environ['ARTIFACT_DIR']}/{platform}").mkdir(parents=True, exist_ok=True)
        with Path(platform_artifact_dir, "base_image.json").open(
            "w", encoding="utf-8"
        ) as f:
            json.dump(base_image_info, f)


if __name__ == "__main__":
    dsop_project = DsopProject()
    hardening_manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    potential_platforms = hardening_manifest.architecture
    # The hardening_manifest doesn't have an architecture section, default to amd64.
    if hardening_manifest.architecture == None:
        platforms = ["amd64"]
    else:
        platforms = [
            platform
            for platform in potential_platforms
        ]
    for platform in platforms:
        log.info(f"Validating image for {platform} architecture.")
        asyncio.run(main(platform))
