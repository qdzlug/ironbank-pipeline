import sys
import os
import logging
import re
from pathlib import Path
from typing import Dict
from dataclasses import dataclass


@dataclass
class Project:
    project_path: str = os.environ.get("CI_PROJECT_PATH")
    # logger: logger


@dataclass
class CHT_Project(Project):
    hardening_manifest_path: Path = Path("hardening_manifest.yaml")
    license_path: Path = Path("LICENSE")
    readme_path: Path = Path("README.md")
    dockerfile_path: Path = Path("Dockerfile")
    trufflehog_conf_path: Path = (
        Path("trufflehog_config.yaml")
        if Path("trufflehog_config.yaml").exists()
        else None
    )
    trufflehog_conf_path: Path = (
        Path("trufflehog_config.yml")
        if Path("trufflehog_config.yml").exists()
        else None
    )
    clamav_wl_path: Path = (
        Path("clamav-whitelist") if Path("clamav-whitelist").exists() else None
    )

    def validate_files_exist(self):
        assert self.license.exists(), "LICENSE not found"
        assert self.readme.exists(), "README.md not found"
        assert self.dockerfile.exists(), "Dockerfile not found"
        assert (
            self.hardening_manifest_path.exists()
        ), "hardening_manifest.yaml not found"
        assert not Path(
            "Jenkinsfile"
        ).exists(), (
            "Jenkinsfile found, please remove this file before rerunning your pipeline"
        )
        assert not Path(
            "download.yaml"
        ), "download.yaml found, this file is no longer supported"
        assert not Path(
            "download.json"
        ), "download.json found, this file is no longer supported"

    def validate_clamav_whitelist_config(self):
        if os.environ.get("CLAMAV_WHITELIST") and not self.clamav_wl:
            logging.error(
                "clamav-whitelist file found but CLAMAV_WHITELIST CI variable does not exist"
            )
            sys.exit(1)
        if self.clamav_wl and not os.environ.get("CLAMAV_WHITELIST"):
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

    def validate_dockerfile(self):
        with self.dockerfile.open("r") as f:
            for line in f.readlines():
                assert not re.findall(
                    "^\s*LABEL", line
                ), "LABEL found in Dockerfile, move all LABELs to the hardening_manifest.yaml file"
