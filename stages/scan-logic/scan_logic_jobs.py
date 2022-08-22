#!/usr/bin/env python3

from base64 import b64decode
import os
import pathlib
import tempfile
import image_verify
from pathlib import Path

from ironbank.pipeline.utils import logger
from ironbank.pipeline.artifacts import ORASArtifact
from ironbank.pipeline.utils.exceptions import ORASDownloadError
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser

log = logger.setup("scan_logic_jobs")


def main():

    sbom_path = Path(os.environ["ARTIFACT_STORAGE"], "sbom/sbom-json.json")
    access_log_path = Path(os.environ["ARTIFACT_STORAGE"], "build/access_log")

    log.info("Parsing new packages")
    new_pkgs = set(
        AccessLogFileParser.parse(access_log_path) + SbomFileParser.parse(sbom_path)
    )
    log.info("New packages parsed:")
    for pkg in new_pkgs:
        log.info(f"  {pkg}")

    # TODO: Future - flush out logic for forced rescan
    if os.getenv("FORCE_SCAN"):
        log.info("Force scan new image")
        return

    with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config_dir:

        docker_config = pathlib.Path(docker_config_dir, "config.json")
        # Save docker auth to config file
        pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode("UTF-8")
        docker_config.write_text(pull_auth)

        old_img = image_verify.diff_needed(docker_config_dir)

        # TODO: Future - Might need to make diff_needed return old_img creation date label
        # If reusing old img for scanning, propagate old date
        # else propagate new date

        if old_img:
            log.info("SBOM diff required to determine image to scan")

            with tempfile.TemporaryDirectory(prefix="ORAS-") as oras_download:
                parse_old_pkgs = True
                try:
                    log.info(f"Downloading artifacts for image: {old_img}")
                    ORASArtifact.download(old_img, oras_download, docker_config_dir)
                    log.info(f"Artifacts downloaded to temp directory: {oras_download}")
                except ORASDownloadError as e:
                    parse_old_pkgs = False
                    log.error(e)

                if parse_old_pkgs:
                    old_sbom = Path(oras_download, "sbom-json.json")
                    old_access_log = Path(oras_download, "access_log")

                    log.info("Parsing old packages")
                    if old_access_log.exists():
                        old_pkgs = set(
                            AccessLogFileParser.parse(old_access_log)
                            + SbomFileParser.parse(old_sbom)
                        )
                    else:
                        log.info("Access log doesn't exist - parsing SBOM only")
                        old_pkgs = set(SbomFileParser.parse(old_sbom))
                    log.info("Old packages parsed:")
                    for pkg in old_pkgs:
                        log.info(f"  {pkg}")

                    if new_pkgs.symmetric_difference(old_pkgs):
                        log.info(f"Packages added: {new_pkgs - old_pkgs}")
                        log.info(f"Packages removed: {old_pkgs - new_pkgs}")
                        log.info("Package(s) difference detected - Must scan new image")
                    else:
                        log.info("Package lists match - Able to scan old image")
                else:
                    log.info("ORAS download failed - Must scan new image")

            # TODO: Future - set env var RESCAN_REQUIRED=true

        else:
            log.info("Image verify failed - Must scan new image")


if __name__ == "__main__":
    main()
