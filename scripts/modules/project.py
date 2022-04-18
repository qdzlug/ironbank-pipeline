import sys
import os
import re
from pathlib import Path
from dataclasses import dataclass

from utils import logger


@dataclass
class Project:
    log = logger.setup(name="Project")
    project_path: str = os.environ.get("CI_PROJECT_PATH")


@dataclass
class DsopProject(Project):
    log = logger.setup(name="Project.DsopProject")
    hardening_manifest_path: Path = Path("hardening_manifest.yaml")
    license_path: Path = Path("LICENSE")
    readme_path: Path = Path("README.md")
    dockerfile_path: Path = Path("Dockerfile")
    trufflehog_conf_path: Path = (
        Path("trufflehog-config.yaml")
        if Path("trufflehog-config.yaml").exists()
        else Path("trufflehog-config.yml")
    )
    clamav_wl_path: Path = Path("clamav-whitelist")

    def validate_files_exist(self) -> None:
        assert self.license_path.exists(), "LICENSE not found"
        assert self.readme_path.exists(), "README.md not found"
        assert self.dockerfile_path.exists(), "Dockerfile not found"
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
        ).exists(), "download.yaml found, this file is no longer supported"
        assert not Path(
            "download.json"
        ).exists(), "download.json found, this file is no longer supported"

    def validate_clamav_whitelist_config(self) -> None:
        if os.environ.get("CLAMAV_WHITELIST") and not self.clamav_wl_path.exists():
            self.log.error(
                "CLAMAV_WHITELIST CI variable exists but clamav-whitelist file not found"
            )
            sys.exit(1)
        if self.clamav_wl_path.exists() and not os.environ.get("CLAMAV_WHITELIST"):
            self.log.error(
                "clamav-whitelist file found but CLAMAV_WHITELIST CI variable does not exist"
            )
            sys.exit(1)

    def validate_trufflehog_config(self) -> None:
        assert not Path(
            "trufflehog.yaml"
        ).exists(), "trufflehog.yaml is not permitted to exist in repo"
        if self.trufflehog_conf_path.exists() and not os.environ.get(
            "TRUFFLEHOG_CONFIG"
        ):
            self.log.error(
                "trufflehog-config file found but TRUFFLEHOG_CONFIG CI variable does not exist"
            )
            sys.exit(1)

    # TODO: Consider moving this to a separate "Dockerfile" module
    def validate_dockerfile(self) -> None:
        with self.dockerfile_path.open("r") as f:
            for line in f.readlines():
                assert not re.findall(
                    r"^\s*LABEL", line
                ), "LABEL found in Dockerfile, move all LABELs to the hardening_manifest.yaml file"
