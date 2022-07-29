#!/usr/bin/env python3

import os
import shutil
import package_compare
import image_verify
from pathlib import Path

from ironbank.pipeline.utils import logger

log = logger.setup("rescan_or_rebuild_jobs")


def main():

    sbom_path = Path(os.environ["ARTIFACT_STORAGE"], "sbom/sbom-json.json")
    access_log_path = Path(os.environ["ARTIFACT_STORAGE"], "build/access_log")

    log.info("Parsing new packages")
    new_pkgs = package_compare.parse_packages(sbom_path, access_log_path)
    log.info(f"New packages parsed: {new_pkgs}")

    # TODO: Future - flush out logic for forced rebuild
    if os.getenv("FORCE_REBUILD"):
        log.info("Force Rebuild Set")
        return

    old_img = image_verify.diff_needed()

    # TODO: Future - Might need to make diff_needed return old_img creation date label
    # If reusing old img for scanning, propagate old date
    # else propagate new date

    if old_img:
        log.info("SBOM diff required to determine rescan or rebuild")
        tmp_dir = Path(package_compare.download_artifacts(old_img))

        log.info("Parsing old packages")
        old_pkgs = package_compare.parse_packages(
            Path(tmp_dir, "sbom-json.json"), Path(tmp_dir, "access_log")
        )

        if not package_compare.compare_equal(new_pkgs, old_pkgs):
            log.info("Rebuild required!")

        # TODO: Future - set env var REBUILD_REQUIRED=true

        # Cleanup temp directory
        shutil.rmtree(tmp_dir)
    else:
        log.info("No SBOM diff required. Must rebuild image")


if __name__ == "__main__":
    main()
