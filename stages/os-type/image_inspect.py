#!/usr/bin/env python3

import os
import sys
from pathlib import Path

from pipeline.container_tools.skopeo import Skopeo
from pipeline.hardening_manifest import HardeningManifest
from pipeline.image import Image
from pipeline.project import DsopProject
from pipeline.utils.exceptions import GenericSubprocessError
from common.utils import logger

log = logger.setup("pipeline_trigger")


def template_type(os_type: str) -> None:
    """Writes the template type to an env file, based on the os_type var."""
    template_dict = {
        "alpine317-container": "alpine.yaml",
        "alpine3-container": "alpine.yaml",
        "chainguard-container": "chainguard.yaml",
        "debian11-container": "debian11.yaml",
        "debian12-container": "debian12.yaml",
        "distroless-container": "distroless.yaml",
        "scratch-container": "distroless.yaml",
        "sle15-bci-container": "suse.yaml",
        "ubi7-container": "ubi.yaml",
        "ubi8-container": "ubi.yaml",
        "ubi9-container": "ubi.yaml",
        "ubuntu2004-container": "ubuntu2004.yaml",
        # "ubuntu2204-container": "ubuntu2204.yaml", #TODO STIG TYPE PROFILE
    }
    template = template_dict.get(os_type)
    if not template:
        log.error("Unknown template type for os-type: %s", os_type)
        sys.exit(1)
    log.info("Using pipeline template: %s", template)
    with Path("template.env").open(mode="w", encoding="utf-8") as f:
        f.write(f"TEMPLATE={template}\n")
        f.write(f"OS_TYPE={os_type}\n")


def get_registry_info() -> tuple[str, str]:
    """Returns a tuple of pull auth file path and registry project."""
    return (
        (
            os.environ["DOCKER_AUTH_FILE_PRE_PUBLISH"],
            os.environ["REGISTRY_PRE_PUBLISH_URL"],
        )
        if os.environ.get("STAGING_BASE_IMAGE")
        else (
            os.environ["DOCKER_AUTH_FILE_PULL"],
            os.environ["BASE_REGISTRY"],
        )
    )


def main():
    """Image-inspect main method."""
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
