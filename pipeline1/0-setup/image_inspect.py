#!/usr/bin/env python3

import os
import sys
from pathlib import Path

from common.utils import logger
from pipeline.container_tools.skopeo import Skopeo
from pipeline.hardening_manifest import HardeningManifest
from pipeline.image import Image
from pipeline.project import DsopProject
from pipeline.utils.exceptions import GenericSubprocessError

log = logger.setup("pipeline_trigger")


def template_type(os_type: str) -> None:
    """Writes the template type to an env file, based on the os_type var."""
    template_dict = {
        # PEP8 discourages \ and gitlab wants no blank lines
        "alpine317-container": (
            'DISTRO_REPO_DIR=apk-repos/repositories\n'
            'DISTRO_REPO_MOUNT=/etc/apk/repositories\n'
            'OS_TYPE=alpine317-container'
        ),
        "alpine3-container": (
            'DISTRO_REPO_DIR=apk-repos/repositories\n'
            'DISTRO_REPO_MOUNT=/etc/apk/repositories\n'
            'OS_TYPE=alpine3-container'
        ),
        "chainguard-container": (
            'OS_TYPE=chainguard'
        ),
        "debian11-container": (
            'DISTRO_REPO_DIR=debian-repos/11-bullseye-ironbank.list\n'
            'DISTRO_REPO_MOUNT=/etc/apt/sources.list\n'
            'OS_TYPE=debian11-container\n'
            'OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_anssi_np_nt28_average\n'
            'OSCAP_DATASTREAM=ssg-debian11-ds.xml\n'
            'OSCAP_SCANNER=debian'
        ),
        "debian12-container": (
            'DISTRO_REPO_DIR=debian-repos/12-bookworm-debian.sources\n'
            'DISTRO_REPO_MOUNT=/etc/apt/sources.list.d/debian.sources\n'
            'OS_TYPE=debian12-container\n'
            'OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_anssi_np_nt28_average\n'
            'OSCAP_DATASTREAM=ssg-debian12-ds.xml\n'
            'OSCAP_SCANNER=debian'
        ),
        "distroless-container": (
            'OS_TYPE=distroless-container'
        ),
        "scratch-container": (
            'OS_TYPE=scratch-container'
        ),
        "sle15-bci-container": (
            'DISTRO_REPO_DIR=zypper-repos\n'
            'DISTRO_REPO_MOUNT=/etc/zypp/repos.d\n'
            'OS_TYPE=sle15-bci-container\n'
            'OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig\n'
            'OSCAP_DATASTREAM=ssg-sle15-ds.xml\n'
            'OSCAP_OVAL=pub-projects-security-oval-suse.linux.enterprise.15.xml\n'
            'OSCAP_SCANNER=suse'
        ),
        "ubi7-container": (
            'DISTRO_REPO_DIR=ubi-repos\n'
            'DISTRO_REPO_MOUNT=/etc/yum.repos.d\n'
            'OS_TYPE=ubi7-container\n'
            'OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig\n'
            'OSCAP_DATASTREAM=ssg-rhel7-ds.xml\n'
            'OSCAP_OVAL=security-data-oval-v2-RHEL7-rhel-7.oval.xml.bz2'
        ),
        "ubi8-container": (
            'DISTRO_REPO_DIR=ubi-repos\n'
            'DISTRO_REPO_MOUNT=/etc/yum.repos.d\n'
            'OS_TYPE=ubi8-container\n'
            'OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig\n'
            'OSCAP_DATASTREAM=ssg-rhel8-ds.xml\n'
            'OSCAP_OVAL=security-data-oval-v2-RHEL8-rhel-8.oval.xml.bz2'
        ),
        "ubi9-container": (
            'DISTRO_REPO_DIR=ubi-repos\n'
            'DISTRO_REPO_MOUNT=/etc/yum.repos.d\n'
            'OS_TYPE=ubi9-container\n'
            'OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_stig\n'
            'OSCAP_DATASTREAM=ssg-rhel9-ds.xml\n'
            'OSCAP_OVAL=security-data-oval-v2-RHEL9-rhel-9.oval.xml.bz2'
        ),
        "ubuntu2004-container": (
            'DISTRO_REPO_DIR=apt-repos/2004-focal-ironbank.list\n'
            'DISTRO_REPO_MOUNT=/etc/apt/sources.list\n'
            'OS_TYPE=ubuntu2004-container\n'
            'OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_anssi_np_nt28_average\n'
            'OSCAP_DATASTREAM=ssg-ubuntu2004-ds.xml\n'
            'OSCAP_SCANNER=debian'
        ),
        "ubuntu2204-container": (
            'DISTRO_REPO_DIR=apt-repos/2204-jammy-ironbank.list\n'
            'DISTRO_REPO_MOUNT=/etc/apt/sources.list\n'
            'OS_TYPE=ubuntu2204-container\n'
            'OSCAP_PROFILE=xccdf_org.ssgproject.content_profile_anssi_np_nt28_average\n'
            'OSCAP_DATASTREAM=ssg-ubuntu2204-ds.xml\n'
            'OSCAP_SCANNER=debian'
        ),
    }
    template = template_dict.get(os_type)
    if not template:
        log.error("Unknown template for os-type: %s", os_type)
        sys.exit(1)
    log.info("Using pipeline template: %s", template)
    with Path("os.env").open(mode="w", encoding="utf-8") as f:
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