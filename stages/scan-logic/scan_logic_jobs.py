#!/usr/bin/env python3

import os
import sys
import json
import pathlib
import tempfile
import image_verify
from pathlib import Path
from base64 import b64decode
from ironbank.pipeline.image import Image

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.types import Package
from ironbank.pipeline.container_tools.cosign import Cosign
from ironbank.pipeline.utils.exceptions import CosignDownloadError
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser

log = logger.setup("scan_logic_jobs")


def write_env_vars(
    image_name_tag: str, commit_sha: str, digest: str, build_date: str
) -> None:
    log.info("Writing env variables to file")
    with pathlib.Path("scan_logic.env").open("w") as f:
        f.writelines(
            [
                f"IMAGE_TO_SCAN={image_name_tag}\n",
                f"COMMIT_SHA_TO_SCAN={commit_sha}\n",
                f"DIGEST_TO_SCAN={digest}\n",
                f"BUILD_DATE_TO_SCAN={build_date}",
            ]
        )


def parse_packages(sbom: Path | dict, access_log: Path | list[str]) -> list[Package]:
    """
    Verify sbom and access log files exist and parse packages accordingly
    """
    # Pipeline should fail if sbom does not exist (exception not caught)
    pkgs = set(SbomFileParser.parse(sbom))
    try:
        pkgs.update(AccessLogFileParser.parse(access_log))
    except FileNotFoundError:
        log.info("Access log does not exist")
    log.info("Packages parsed:")
    for pkg in pkgs:
        log.info(f"  {pkg}")
    return pkgs


def download_artifacts(image: Image, output_dir: Path, docker_config_dir: Path) -> bool:
    """
    Download cosign attestation and save predicates for sbom & hardening manifest to files
    """
    try:
        log.info(f"Downloading artifacts for image: {image}")
        # Download syft sbom (json) & hardening manifest (json)
        Cosign.download(
            image,
            output_dir,
            docker_config_dir,
            [
                "https://github.com/anchore/syft#output-formats",
                "https://repo1.dso.mil/dsop/dccscr/-/raw/master/hardening%20manifest/README.md",
            ],
            log_cmd=True,
        )
        log.info(f"Artifacts downloaded to temp directory: {output_dir}")
    except CosignDownloadError as e:
        log.error(e)
        return False
    return True


def get_old_pkgs(
    image_name: str, image_digest: str, docker_config_dir: Path
) -> list[Package]:
    """
    Return list of packages parsed from old image sbom & access log
    """
    old_img = Image(
        registry=os.environ["BASE_REGISTRY"],
        name=image_name,
        digest=image_digest,
    )

    with tempfile.TemporaryDirectory(prefix="COSIGN-") as cosign_download:
        if download_artifacts(
            image=old_img,
            output_dir=cosign_download,
            docker_config_dir=docker_config_dir,
        ):
            old_sbom = Path(cosign_download, "sbom-syft-json.json")

            # Parse access log from hardening manifest
            with Path(cosign_download, "hardening_manifest.json").open("r") as hm:
                old_access_log = json.load(hm)["access_log"].split("\n")

            log.info("Parsing old packages")
            return parse_packages(old_sbom, old_access_log)
        else:
            log.info("Download attestations failed")
            return []


def main():
    image_name = os.environ["IMAGE_NAME"]
    image_name_tag = os.environ["IMAGE_FULLTAG"]
    new_sbom = Path(os.environ["ARTIFACT_STORAGE"], "sbom/sbom-syft-json.json")
    new_access_log = Path(os.environ["ARTIFACT_STORAGE"], "build/access_log")

    write_env_vars(
        image_name_tag,
        os.environ["CI_COMMIT_SHA"].lower(),
        os.environ["IMAGE_PODMAN_SHA"],
        os.environ["BUILD_DATE"],
    )
    log.info("New image name, tag, digest, and build date saved")

    log.info("Parsing new packages")
    new_pkgs = parse_packages(new_sbom, new_access_log)

    if os.environ.get("FORCE_SCAN_NEW_IMAGE"):
        log.info("Skip Logic: Force scan new image")
    elif os.environ["CI_COMMIT_BRANCH"] != "master":
        log.info("Skip Logic: Non-master branch")
    else:
        with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:
            # TODO: Make generating docker config file a module and reuse?
            # ------
            docker_config = pathlib.Path(docker_config_dir, "config.json")
            # Save docker auth to config file
            pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode("UTF-8")
            docker_config.write_text(pull_auth)
            # ---------

            old_image_details = image_verify.diff_needed(docker_config_dir)
            if not old_image_details:
                log.info("Image verify failed - Must scan new image")
                sys.exit(0)

            log.info("SBOM diff required to determine image to scan")

            old_pkgs = get_old_pkgs(
                image_name=image_name,
                image_digest=old_image_details["digest"],
                docker_config_dir=docker_config_dir,
            )
            if not old_pkgs:
                log.info("No old pkgs to compare - Must scan new image")
                sys.exit(0)

            if new_pkgs.symmetric_difference(old_pkgs):
                log.info(f"Packages added: {new_pkgs - old_pkgs}")
                log.info(f"Packages removed: {old_pkgs - new_pkgs}")
                log.info("Package(s) difference detected - Must scan new image")
            else:
                log.info("Package lists match - Able to scan old image")
                # Override image to scan with old tag
                image_name_tag = f"{os.environ['BASE_REGISTRY']}/{image_name}:{old_image_details['tag']}"
                write_env_vars(
                    image_name_tag,
                    old_image_details["commit_sha"],
                    old_image_details["digest"],
                    old_image_details["build_date"],
                )
                log.info("Old image name, tag, digest, and build date saved")


if __name__ == "__main__":
    main()
