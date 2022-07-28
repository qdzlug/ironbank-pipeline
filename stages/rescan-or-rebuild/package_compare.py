#!/usr/bin/env python3

import tempfile
from pathlib import Path
from ironbank.pipeline.utils import logger
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser

log = logger.setup(name="package_compare")


def parse_packages(sbom_path: Path, access_log_path: Path) -> set:
    pkgs = AccessLogFileParser.parse(access_log_path)
    pkgs += SbomFileParser.parse(sbom_path)
    return set(pkgs)


def download_artifacts(img_path: str) -> str:
    log.info(f"Downloading artifacts for image: {img_path}")

    # TODO: Make tmp directory
    tmp_dir = tempfile.TemporaryDirectory()

    # TODO: Download old artifacts to tmp directory

    # TODO: cosign-cert should exist elsewhere in pipeline - don't use url
    # artifact=$(cosign triangulate --type sbom img_path)
    # cosign verify --cert https://repo1.dso.mil/ironbank-tools/ironbank-pipeline/-/raw/master/scripts/cosign/cosign-certificate.pem "${artifact}"
    # pass tmp_dir to subprocess as current dir
    # oras pull --allow-all "${artifact}"

    log.info(f"Artifacts downloaded to temp directory: {tmp_dir.name}")
    return tmp_dir.name


def compare_equal(new_pkgs, old_pkgs) -> bool:
    # Check for package differences
    if new_pkgs.symmetric_difference(old_pkgs):
        # Log added, removed pkgs
        log.info(f"Packages added: {new_pkgs - old_pkgs}")
        log.info(f"Packages removed: {old_pkgs - new_pkgs}")

        log.info("SBOM difference(s) detected!")
        # scan new image
        return False
    else:
        log.info("No difference detected!")
        # rescan old image
        return True
