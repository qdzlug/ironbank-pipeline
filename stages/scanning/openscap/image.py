import subprocess
from typing import Dict
from dataclasses import dataclass, field
from pathlib import Path
from envs import Envs
from oscap import OpenSCAP
from log import log
from pipeline.utils.decorators import subprocess_error_handler
from pipeline.utils.exceptions import GenericSubprocessError

PROFILE_KEY = "profile"
SECURITY_GUIDE_KEY = "security_guide"
PULL_COMMAND_ERROR = "Pull command failed with error"
GET_IMAGE_PATH_ERROR = "Get image path command failed with error"


@dataclass
class Image:
    """A class to represent an Image object for OpenSCAP scanning.

    This class encapsulates an OpenSCAP object used for scanning and provides
    properties and methods to facilitate the OpenSCAP scanning workflow.

    Attributes
    ----------
    image_type : str
        The type of the imported base image.
    security_guide: Path
        Returns the path to the security guide for the base image.
    profile: str
        Returns the profile for the base image.
    path: Path
        Returns the path to the docker image that has been pulled for scanning.

    Raises
    -----
    ValueError
        If the image type set in through the environment variable is invalid.
    GenericSubprocessError
        If one of the subrocess used to pull the image fails.
    """

    _oscap: OpenSCAP
    base_type: str = field(init=False)
    _supported_images: Dict[str, Dict[str, str]] = field(init=False)
    path: Path = field(init=False)
    security_guide: Path = field(init=False)
    profile: str = field(init=False)

    def __post_init__(self) -> None:
        self._supported_images = self._get_supported_images()
        self.base_type = self._get_type()
        self.path = self._pull()
        self.security_guide_path = self._set_security_guide_path()
        self.profile = self._set_profile()

    def _get_supported_images(self) -> Dict[str, Dict[str, str]]:
        supported_images = {
            image: {
                PROFILE_KEY: "xccdf_org.ssgproject.content_profile_stig",
                SECURITY_GUIDE_KEY: f"scap-security-guide-{self._oscap.version}/ssg-{image.rsplit('-', maxsplit=1)[-1]}-ds.xml",
            }
            # TODO: should be a subset of list in image_inspect.py
            for image in [
                "ubi9-container",
                "ubi9-minimal-container",
                "ubi9-micro-container",
                "ubi8-container",
                "ubi8-minimal-container",
                "ubi8-micro-container",
                "ubi7-container",
                "ubi7-minimal-container",
                "ubuntu2004-container",
                "sle15-bci-container",
            ]
        }

        supported_images["debian11-container"] = {
            PROFILE_KEY: "xccdf_org.ssgproject.content_profile_anssi_np_nt28_average",
            SECURITY_GUIDE_KEY: f"scap-security-guide-{self._oscap.version}/ssg-debian11-ds.xml",
        }
        return supported_images

    def _get_type(self) -> str:
        try:
            base_type = Envs().base_image_type
            if base_type not in self._supported_images:
                raise ValueError(
                    f"The base image type {base_type} provided in the environmental variable 'BASE_IMAGE_TYPE' is not supported. Unable to perform OpenSCAP scan."
                )
            return base_type
        except ValueError as e:
            log.error("Failed to determine base image type: %s", str(e))
            raise

    @subprocess_error_handler(PULL_COMMAND_ERROR)
    def _pull_image(self) -> None:
        docker_auth_file_pull = Envs().docker_auth_file_pull
        image_to_scan = Envs().image_to_scan
        pull_cmd = [
            "podman",
            "pull",
            "--authfile",
            docker_auth_file_pull,
            image_to_scan,
        ]
        subprocess.run(pull_cmd, check=True)

    @subprocess_error_handler(GET_IMAGE_PATH_ERROR)
    def _get_image_path(self) -> Path:
        docker_image_path_cmd = ["podman", "images", "-q"]
        result = subprocess.run(docker_image_path_cmd, check=True)
        result_as_path: Path = Path(result.stdout.decode())
        return result_as_path

    def _pull(self) -> Path:
        try:
            self._pull_image()
        except GenericSubprocessError as exc:
            log.error(f"{PULL_COMMAND_ERROR}: {exc}")
            raise

        try:
            docker_image_path: Path = self._get_image_path()
        except GenericSubprocessError as exc:
            log.error(f"{GET_IMAGE_PATH_ERROR}: {exc}")
            raise

        log.info(f"Docker image path: {docker_image_path}")
        return docker_image_path

    def _set_security_guide_path(self) -> Path:
        guide = Path(self._supported_images[self.base_type][SECURITY_GUIDE_KEY])
        log.info(f"Security Guide: {guide}.")
        return guide

    def _set_profile(self) -> str:
        profile: str = self._supported_images[self.base_type][PROFILE_KEY]
        log.info(f"Profile: {profile}.")
        return profile
