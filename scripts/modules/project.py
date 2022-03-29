from dataclasses import dataclass
from pathlib import Path
from typing import Dict
import sys
import os
import logging


@dataclass
class Project:
    hardening_manifest: Path = Path("hardening_manifest.yaml")
    license: Path = Path("LICENSE")
    readme: Path = Path("README.md")
    dockerfile: Path = Path("Dockerfile")
    trufflehog_conf: Path = (
        Path("trufflehog_config.yaml")
        if Path("trufflehog_config.yaml").exists()
        else None
    )
    trufflehog_conf = (
        Path("trufflehog_config.yml")
        if Path("trufflehog_config.yml").exists()
        else None
    )
    clamav_wl: Path = (
        Path("clamav-whitelist") if Path("clamav-whitelist").exist() else None
    )

    def validate_files_exist(self):
        assert self.license.exists()
        assert self.readme.exists()
        assert self.dockerfile.exists()
        assert self.hardening_manifest_path.exists()
        assert Path("Jenkinsfile").exists()

    def validate_clamav_whitelist_config(self):
        if os.environ["CLAMAV_WHITELIST"] and not self.clamav_wl:
            logging.error(
                "CLAMAV_WHITELIST CI variable exists but clamav-whitelist file not found"
            )
            sys.exit(1)

    def validate_trufflehog_config(self):
        assert not Path("trufflehog.yaml").exists()
        if self.trufflehog_conf_path and not os.environ["TRUFFLEHOG_CONFIG"]:
            logging.error(
                "trufflehog-config file found but TRUFFLEHOG_CONFIG CI variable does not exist"
            )
            sys.exit(1)
