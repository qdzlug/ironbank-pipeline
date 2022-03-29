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
        assert self.license.exists(), "LICENSE not found"
        assert self.readme.exists(), "README.md not found"
        assert self.dockerfile.exists(), "Dockerfile not found"
        assert (
            self.hardening_manifest_path.exists()
        ), "hardening_manifest.yaml not found"
        assert Path(
            "Jenkinsfile"
        ).exists(), (
            "Jenkinsfile found, please remove this file before rerunning your pipeline"
        )

    def validate_clamav_whitelist_config(self):
        bail = False
        if os.environ.get("CLAMAV_WHITELIST") and not self.clamav_wl:
            bail = True
        if self.clamav_wl and not os.environ.get("CLAMAV_WHITELIST"):
            bail = True
        if bail:
            logging.error(
                "CLAMAV_WHITELIST CI variable exists but clamav-whitelist file not found"
            )
            sys.exit(1)

    def validate_trufflehog_config(self):
        assert not Path(
            "trufflehog.yaml"
        ).exists(), "trufflehog.yaml is not permitted to exist in repo"
        if self.trufflehog_conf_path and not os.environ.get("TRUFFLEHOG_CONFIG"):
            logging.error(
                "trufflehog-config file found but TRUFFLEHOG_CONFIG CI variable does not exist"
            )
            sys.exit(1)
