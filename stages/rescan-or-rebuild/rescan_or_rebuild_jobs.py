#!/usr/bin/env python3

from base64 import b64decode
import os
import pathlib
import tempfile
import package_compare
import image_verify
from pathlib import Path

from ironbank.pipeline.utils import logger
from ironbank.pipeline.artifacts import ORASArtifact

log = logger.setup("rescan_or_rebuild_jobs")


def main():

    sbom_path = Path(os.environ["ARTIFACT_STORAGE"], "sbom/sbom-json.json")
    access_log_path = Path(os.environ["ARTIFACT_STORAGE"], "build/access_log")

    log.info("Parsing new packages")
    new_pkgs = package_compare.parse_packages(sbom_path, access_log_path)
    log.info("New packages parsed:")
    for pkg in new_pkgs:
        log.info(f"  {pkg}")

    # TODO: Future - flush out logic for forced rebuild
    if os.getenv("FORCE_REBUILD"):
        log.info("Force Rebuild Set")
        return

    with tempfile.TemporaryDirectory(prefix="DOCKER_CONFIG-") as docker_config:

        auth_file = pathlib.Path(docker_config, "prod_pull_auth.json")
        # Grab staging docker auth
        pull_auth = b64decode(os.environ["DOCKER_AUTH_CONFIG_PULL"]).decode("UTF-8")
        auth_file.write_text(pull_auth)

        old_img = image_verify.diff_needed(docker_config)

        # TODO: Future - Might need to make diff_needed return old_img creation date label
        # If reusing old img for scanning, propagate old date
        # else propagate new date

        if old_img:
            log.info("SBOM diff required to determine rescan or rebuild")

            with tempfile.TemporaryDirectory(prefix="ORAS-") as oras_download:

                ORASArtifact.download(old_img, oras_download, docker_config)

                log.info("Parsing old packages")
                old_pkgs = package_compare.parse_packages(
                    Path(oras_download, "sbom-json.json"),
                    Path(oras_download, "access_log"),
                )
                log.info("Old packages parsed:")
                for pkg in old_pkgs:
                    log.info(f"  {pkg}")

            if not package_compare.compare_equal(new_pkgs, old_pkgs):
                log.info("Rebuild required")

            # TODO: Future - set env var REBUILD_REQUIRED=true

        else:
            log.info("No SBOM diff required. Rebuild required")


if __name__ == "__main__":
    main()
