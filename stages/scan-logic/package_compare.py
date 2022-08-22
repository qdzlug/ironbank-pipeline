#!/usr/bin/env python3

from pathlib import Path
from ironbank.pipeline.utils import logger
from ironbank.pipeline.file_parser import AccessLogFileParser, SbomFileParser

log = logger.setup(name="package_compare")


def parse_packages(sbom_path: Path, access_log_path: Path) -> set:
    pkgs = AccessLogFileParser.parse(access_log_path)
    pkgs += SbomFileParser.parse(sbom_path)
    return set(pkgs)


def compare_equal(new_pkgs, old_pkgs) -> bool:
    # Check for package differences
    if new_pkgs.symmetric_difference(old_pkgs):
        # Log added, removed pkgs
        log.info(f"Packages added: {new_pkgs - old_pkgs}")
        log.info(f"Packages removed: {old_pkgs - new_pkgs}")
        return False
    else:
        return True
