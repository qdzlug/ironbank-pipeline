#!/usr/bin/env python3

from base64 import b64decode
import os
import pathlib
import sys
import tempfile
import image_verify
from pathlib import Path

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.types import Package
from ironbank.pipeline.artifacts import ORASArtifact
from ironbank.pipeline.utils.exceptions import ORASDownloadError
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser

log = logger.setup("scan_logic_jobs")


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


def main():
    image_name = os.environ["IMAGE_NAME"]
    new_sbom = Path(os.environ["ARTIFACT_STORAGE"], "sbom/sbom-json.json")
    new_access_log = Path(os.environ["ARTIFACT_STORAGE"], "build/access_log")

    log.info("Parsing new packages")
    new_pkgs = parse_packages(new_sbom, new_access_log)

    scan_new_image = True

    if os.environ.get("FORCE_SCAN_NEW_IMAGE"):
        # Leave scan_new_image set to True and log
        log.info("Force scan new image")
    else:
        with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:

            docker_config = pathlib.Path(docker_config_dir, "config.json")
            # Save docker auth to config file
            pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode("UTF-8")
            docker_config.write_text(pull_auth)

            old_image_details = image_verify.diff_needed(docker_config_dir)

            if old_image_details:
                # Unpack returned tuple into variables
                (old_img_digest, old_img_build_date) = old_image_details

                log.info("SBOM diff required to determine image to scan")

                with tempfile.TemporaryDirectory(prefix="ORAS-") as oras_download:
                    parse_old_pkgs = True
                    try:
                        old_img = f"{os.environ['BASE_REGISTRY']}/{image_name}@{old_img_digest}"
                        log.info(f"Downloading artifacts for image: {old_img}")
                        ORASArtifact.download(old_img, oras_download, docker_config_dir)
                        log.info(
                            f"Artifacts downloaded to temp directory: {oras_download}"
                        )
                    except ORASDownloadError as e:
                        parse_old_pkgs = False
                        log.error(e)

                    if parse_old_pkgs:
                        old_sbom = Path(oras_download, "sbom-json.json")
                        old_access_log = Path(oras_download, "access_log")

                        log.info("Parsing old packages")
                        old_pkgs = parse_packages(old_sbom, old_access_log)

                        if new_pkgs.symmetric_difference(old_pkgs):
                            log.info(f"Packages added: {new_pkgs - old_pkgs}")
                            log.info(f"Packages removed: {old_pkgs - new_pkgs}")
                            log.info(
                                "Package(s) difference detected - Must scan new image"
                            )
                        else:
                            log.info("Package lists match - Able to scan old image")
                            scan_new_image = False
                    else:
                        log.info("ORAS download failed - Must scan new image")
            else:
                log.info("Image verify failed - Must scan new image")

    log.info("Writing env variables to file")
    with open(Path(os.environ["SCAN_LOGIC_DIR"], "scan_logic.env"), "w") as f:
        if scan_new_image:
            f.writelines(
                [
                    f"IMAGE_TO_SCAN={image_name}",
                    f'DIGEST={os.environ["IMAGE_PODMAN_SHA"]}',
                    f'BUILD_DATE={os.environ["BUILD_DATE"]}',
                ]
            )
            log.info("New image digest and build date saved")
        else:
            f.writelines(
                [
                    f"IMAGE_TO_SCAN={image_name}",
                    f"DIGEST={old_img_digest}",
                    f"BUILD_DATE={old_img_build_date}",
                ]
            )
            log.info("Old image digest and build date saved")

if __name__ == "__main__":
    main()
