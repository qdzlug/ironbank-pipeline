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
        "alpine317-container": """
DISTRO_REPO_DIR="apk-repos/repositories"
DISTRO_REPO_MOUNT="/etc/apk/repositories"
OS_TYPE="alpine317-container"
""",
        "alpine3-container": """
DISTRO_REPO_DIR="apk-repos/repositories"
DISTRO_REPO_MOUNT="/etc/apk/repositories"
OS_TYPE="alpine3-container"
""",
        "chainguard-container": """
OS_TYPE="chainguard"
""",
        "debian11-container": """
DISTRO_REPO_DIR="debian-repos/11-bullseye-ironbank.list"
DISTRO_REPO_MOUNT="/etc/apt/sources.list"
OS_TYPE="debian11-container"
""",
        "debian12-container": """
DISTRO_REPO_DIR="debian-repos/12-bookworm-debian.sources"
DISTRO_REPO_MOUNT="/etc/apt/sources.list.d/debian.sources"
OS_TYPE="debian12-container"
""",
        "distroless-container": """
OS_TYPE="distroless-container"
""",
        "scratch-container": """
OS_TYPE="scratch-container"
""",
        "sle15-bci-container": """
DISTRO_REPO_DIR="zypper-repos"
DISTRO_REPO_MOUNT="/etc/zypp/repos.d"
OS_TYPE="sle15-bci-container"
""",
        "ubi7-container": """
DISTRO_REPO_DIR="ubi-repos"
DISTRO_REPO_MOUNT="/etc/yum.repos.d"
OS_TYPE="ubi7-container"
""",
        "ubi8-container": """
DISTRO_REPO_DIR="ubi-repos"
DISTRO_REPO_MOUNT="/etc/yum.repos.d"
OS_TYPE="ubi8-container"
""",
        "ubi9-container": """
DISTRO_REPO_DIR="ubi-repos"
DISTRO_REPO_MOUNT="/etc/yum.repos.d"
OS_TYPE="ubi9-container"
""",
        "ubuntu2004-container": """
DISTRO_REPO_DIR="apt-repos/2004-focal-ironbank.list"
DISTRO_REPO_MOUNT="/etc/apt/sources.list"
OS_TYPE="ubuntu2004-container"
UBUNTU="1"
""",
        "ubuntu2204-container": """
DISTRO_REPO_DIR="apt-repos/2204-jammy-ironbank.list"
DISTRO_REPO_MOUNT="/etc/apt/sources.list"
OS_TYPE="ubuntu2204-container"
UBUNTU="1"
""",
    }
    template = template_dict.get(os_type)
    if not template:
        log.error("Unknown template type for os-type: %s", os_type)
        sys.exit(1)
    log.info("Using pipeline template: %s", template)
    with Path("template.env").open(mode="w", encoding="utf-8") as f:
        f.write(template)


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
