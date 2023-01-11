#!/usr/bin/env python3

import os
import sys
from pathlib import Path

from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.utils import logger
from ironbank.pipeline.image import Image
from ironbank.pipeline.container_tools.skopeo import Skopeo
from ironbank.pipeline.utils.exceptions import GenericSubprocessError

log = logger.setup("pipeline_trigger")


def template_type(os_type: str) -> None:
    """Writes the template type to an env file, based on the os_type var"""
    template_dict = {
        "alpine317-container": "alpine.yaml",
        "distroless-container": "distroless.yaml",
        "scratch-container": "distroless.yaml",
        "sle15-bci-container": "suse.yaml",
        "ubi7-container": "ubi.yaml",
        "ubi8-container": "ubi.yaml",
        "ubi9-container": "ubi.yaml",
        "ubuntu2004-container": "ubuntu.yaml",
    }
    template = template_dict.get(os_type)
    if not template:
        log.error("Unknown template type for os-type: %s", os_type)
        sys.exit(1)
    log.info("Using pipeline template: %s", template)
    with Path("template.env").open(mode="w", encoding="utf-8") as f:
        f.write(f"TEMPLATE={template}\n")
        f.write(f"BASE_IMAGE_TYPE={os_type}\n")
        f.write(f"TARGET_BRANCH={os.environ['TARGET_BRANCH']}\n")
        f.write(f"LOGLEVEL={os.environ.get('LOGLEVEL', 'INFO')}")


def get_registry_info() -> tuple[str, str]:
    """returns a tuple of pull auth file path and registry project"""
    if os.environ.get("STAGING_BASE_IMAGE"):
        # Grab staging pull docker auth
        pull_auth = os.environ["DOCKER_AUTH_CONFIG_FILE_STAGING"]
        registry = os.environ["REGISTRY_URL_STAGING"]
    else:
        # Grab prod docker auth
        pull_auth = os.environ["DOCKER_AUTH_CONFIG_FILE_PULL"]
        registry = os.environ["REGISTRY_URL_PROD"]
    return pull_auth, registry


def main():
    """image-inspect main method"""
    os_label = "mil.dso.ironbank.os-type"
    dsop_project = DsopProject()
    manifest = HardeningManifest(dsop_project.hardening_manifest_path)
    os_type = manifest.labels.get(os_label)
    if not os_type:
        pull_auth, registry = get_registry_info()
        try:
            skopeo = Skopeo(pull_auth)
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
            log.error("Failed 'skopeo inspect' of image: %s", base_image)
            sys.exit(1)
        os_type = base_img_inspect["Labels"].get(os_label)
    if not os_type:
        log.error("Unknown os-type")
        sys.exit(1)
    log.info("OS_TYPE: %s", os_type)
    template_type(os_type)


if __name__ == "__main__":
    main()
