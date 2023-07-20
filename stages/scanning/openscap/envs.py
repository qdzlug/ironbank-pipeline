import os
from pathlib import Path
from dataclasses import dataclass
from logger import LoggerMixin


# pylint: disable=missing-function-docstring
@dataclass
class Envs(LoggerMixin):
    """A class to get environment variables."""

    def _get(self, name: str) -> str:
        env = os.getenv(name.upper(), "")
        if not env:
            self._log.info(f"Environment variable {name.upper()} is not set.")
        return env

    @property
    def ci_job_url(self) -> str:
        return self._get("CI_JOB_URL")

    @property
    def base_image_type(self) -> str:
        return self._get("BASE_IMAGE_TYPE")

    @property
    def pipeline_repo_dir(self) -> Path:
        return Path(self._get("PIPELINE_REPO_DIR"))

    @property
    def oscap_scans(self) -> Path:
        return Path(self._get("OSCAP_SCANS"))

    @property
    def scap_content(self) -> Path:
        return Path(self._get("SCAP_CONTENT"))

    @property
    def image_to_scan(self) -> str:
        return self._get("IMAGE_TO_SCAN")

    @property
    def scap_url(self) -> str:
        return self._get("SCAP_URL")

    @property
    def docker_auth_file_pull(self) -> str:
        return self._get("DOCKER_AUTH_FILE_PULL")

    @property
    def skip_openscap(self) -> str:
        return self._get("SKIP_OPENSCAP")
