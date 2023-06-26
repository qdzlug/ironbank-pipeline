import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path

from ironbank.pipeline.utils import logger
from ironbank.pipeline.utils.exceptions import SymlinkFoundError


@dataclass
class Project:
    """The base project class that defines a log and project path."""

    log = logger.setup(name="Project")
    project_path: Path = Path(os.environ.get("CI_PROJECT_PATH", "."))


@dataclass
class DsopProject(Project):
    """A subclass of the Project class, with additional file paths and methods
    to validate the DSOP project structure."""

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

    def validate(self) -> None:
        """Performs a series of validation checks on the project structure and
        configuration."""
        self.validate_no_symlinked_files()
        self.validate_files_exist()
        self.validate_trufflehog_config()
        self.validate_dockerfile()

    def validate_no_symlinked_files(self) -> None:
        """Validates that no symlinked files exist within the project.

        Raises a SymlinkFoundError if a symlink is found.
        """
        for key, path_obj in self.__dict__.items():
            if isinstance(path_obj, Path):
                if path_obj.is_symlink():
                    raise SymlinkFoundError(
                        f"Symlink found for {key}, failing pipeline"
                    )

    def validate_files_exist(self) -> None:
        """Validates that all necessary files exist within the project.

        Raises an AssertionError if a necessary file is missing.
        """
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

    def validate_trufflehog_config(self) -> None:
        """Validates the trufflehog configuration.

        Raises an AssertionError if an invalid path is detected.
        """
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
        """Validates the Dockerfile, checking for the presence of certain
        labels.

        Raises an AssertionError if invalid labels are found.
        """
        with self.dockerfile_path.open(mode="r", encoding="utf-8") as f:
            for line in f.readlines():
                assert not re.findall(
                    r"^\s*LABEL", line
                ), "LABEL found in Dockerfile, move all LABELs to the hardening_manifest.yaml file"
