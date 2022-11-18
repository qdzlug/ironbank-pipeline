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


def write_env_vars(image: str, digest: str, build_date: str) -> None:
    log.info("Writing env variables to file")
    with pathlib.Path("scan_logic.env").open("w") as f:
        f.writelines(
            [
                f"IMAGE_TO_SCAN={image}\n",
                f"DIGEST_TO_SCAN={digest}\n",
                f"BUILD_DATE_TO_SCAN={build_date}",
            ]
        )


def parse_packages(sbom_path: Path, access_log_path: Path) -> list[Package]:
    """
    Verify sbom and access log files exist and parse packages accordingly
    """
    if not sbom_path.exists():
        log.info("SBOM not found - Exiting")
        sys.exit(1)
    pkgs = set(SbomFileParser.parse(sbom_path))
    if access_log_path.exists():
        pkgs.update(AccessLogFileParser.parse(access_log_path))
    log.info("Packages parsed:")
    for pkg in pkgs:
        log.info(f"  {pkg}")
    return pkgs


def download_attestations(image: Image, output_dir: Path, docker_config_dir: Path):
    try:
        log.info(f"Downloading artifacts for image: {image}")
        # Download SYFT SBOM JSON
        Cosign.download(
            image,
            output_dir,
            docker_config_dir,
            "https://github.com/anchore/syft#output-formats",
        )
        # Download Hardening Manifest JSON
        Cosign.download(
            image,
            output_dir,
            docker_config_dir,
            "https://repo1.dso.mil/dsop/dccscr/-/raw/master/hardening%20manifest/README.md",
        )
        log.info(f"Artifacts downloaded to temp directory: {output_dir}")
    except CosignDownloadError as e:
        log.error(e)
        return False
    return True


def get_old_pkgs(image_name: str, image_digest: str, docker_config_dir: Path):
    old_img = Image(
        registry=os.environ["BASE_REGISTRY"],
        name=image_name,
        digest=image_digest,
    )

    with tempfile.TemporaryDirectory(prefix="COSIGN-") as cosign_download:
        if download_attestations(
            image=old_img,
            output_dir=cosign_download,
            docker_config_dir=docker_config_dir,
        ):
            old_sbom = Path(cosign_download, "sbom-syft-json.json")
            old_access_log = Path(cosign_download, "access_log")

            # Parse Access Log from HM
            hm = Path(cosign_download, "hardening_manifest.json").open("r")
            with old_access_log.open("w", encoding="utf-8") as f:
                with hm:
                    data = json.load(hm)["access_log"]
                    f.write(data)

            log.info("Parsing old packages")
            return parse_packages(old_sbom, old_access_log)
        else:
            log.info("Download attestations failed")
            return []


def main():
    image_name = os.environ["IMAGE_NAME"]
    new_sbom = Path(os.environ["ARTIFACT_STORAGE"], "sbom/sbom-syft-json.json")
    new_access_log = Path(os.environ["ARTIFACT_STORAGE"], "build/access_log")

    log.info("Parsing new packages")
    new_pkgs = parse_packages(new_sbom, new_access_log)

    scan_new_image = True

    if os.environ.get("FORCE_SCAN_NEW_IMAGE"):
        # Leave scan_new_image set to True and log
        log.info("Force scan new image")
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

            if old_image_details:
                log.info("SBOM diff required to determine image to scan")
                # Unpack returned tuple into variables
                (old_img_digest, old_img_build_date) = old_image_details

                old_pkgs = get_old_pkgs()

                if not old_pkgs:
                    if new_pkgs.symmetric_difference(old_pkgs):
                        log.info(f"Packages added: {new_pkgs - old_pkgs}")
                        log.info(f"Packages removed: {old_pkgs - new_pkgs}")
                        log.info("Package(s) difference detected - Must scan new image")
                    else:
                        log.info("Package lists match - Able to scan old image")
                        write_env_vars(image_name, old_img_digest, old_img_build_date)
                        log.info("Old image digest and build date saved")
                        scan_new_image = False
                else:
                    log.info("No old pkgs to compare - Must scan new image")
            else:
                log.info("Image verify failed - Must scan new image")

    if scan_new_image:
        write_env_vars(
            image_name, os.environ["IMAGE_PODMAN_SHA"], os.environ["BUILD_DATE"]
        )
        log.info("New image digest and build date saved")


if __name__ == "__main__":
    main()
