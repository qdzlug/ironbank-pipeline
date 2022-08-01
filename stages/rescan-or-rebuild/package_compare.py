#!/usr/bin/env python3

import os
import tempfile
from pathlib import Path
from ironbank.pipeline.utils import logger
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser
from ironbank.pipeline.artifacts import ORASArtifact

log = logger.setup(name="package_compare")


def parse_packages(sbom_path: Path, access_log_path: Path) -> set:
    pkgs = AccessLogFileParser.parse(access_log_path)
    pkgs += SbomFileParser.parse(sbom_path)
    return set(pkgs)


def download_artifacts(img_path: str) -> str:
    log.info(f"Downloading artifacts for image: {img_path}")

    # Make tmp dir
    tmp_dir = tempfile.mkdtemp(
        dir=os.environ.get("PIPELINE_REPO_DIR"), prefix="ORASArtifact-"
    )

    # Download old artifacts to tmp directory
    ORASArtifact().download(img_path, tmp_dir)

    log.info(f"Artifacts downloaded to temp directory: {tmp_dir}")

    return tmp_dir


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
