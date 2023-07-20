import subprocess
from dataclasses import dataclass
from typing import List
from image import Image
from envs import Envs
from pipeline.utils.decorators import subprocess_error_handler
from pipeline.utils.exceptions import GenericSubprocessError
from logger import LoggerMixin


@dataclass
class Scanner(LoggerMixin):
    """Class to perform OpenSCAP scanning on a given image using oscap-podman.

    Methods
    -------
    scan(image: Image) -> None:
        Performs the OpenSCAP scan on the provided Image object.

    Parameters
    ----------
    image : Image
        The Image object representing the image to be scanned.
    """

    _image: Image
    # command: List[str] = field(init=False)

    # def __post_init__(self) -> None:
    # TODO: update this once the pylint plugin is updated
    # self.command = self._set_command()

    def scan(self) -> None:
        """Perform OpenSCAP scan on the provided Image object.

        Raises
        ------
        GenericSubprocessError
            If the scan fails.
        """
        try:
            self._run_subprocess()
            self._log.info("Command completed successfully.")
        except GenericSubprocessError:
            self._log.error("The scan failed: {exc}")
            raise

    @subprocess_error_handler("Scan failed.")
    def _run_subprocess(self) -> subprocess.CompletedProcess:
        image = self._image
        docker_image_path: str = image.path.as_posix()
        profile: str = image.profile
        scap_content: str = Envs().scap_content.as_posix()
        security_guide: str = image.security_guide_path.as_posix()

        command: List[str] = [
            "oscap-podman",
            docker_image_path,
            "xccdf",
            "eval",
            "--verbose",
            "ERROR",
            "--fetch-remote-resources",
            "--profile",
            profile,
            "--stig-viewer",
            "compliance_output_report_stigviewer.xml",
            "--results",
            "compliance_output_report.xml",
            "--report",
            "report.html",
            f"{scap_content}/{security_guide}",
        ]

        return subprocess.run(
            command,
            check=True,
        )

    # def _set_command(self) -> List[str]:
    #     image = self._image
    #     docker_image_path: str = image.path.as_posix()
    #     profile: str = image.profile
    #     scap_content: str = Envs().scap_content.as_posix()
    #     security_guide: str = image.security_guide_path.as_posix()

    #     command: List[str] = [
    #         "oscap-podman",
    #         docker_image_path,
    #         "xccdf",
    #         "eval",
    #         "--verbose",
    #         "ERROR",
    #         "--fetch-remote-resources",
    #         "--profile",
    #         profile,
    #         "--stig-viewer",
    #         "compliance_output_report_stigviewer.xml",
    #         "--results",
    #         "compliance_output_report.xml",
    #         "--report",
    #         "report.html",
    #         f"{scap_content}/{security_guide}",
    #     ]

    #     self._log.info(f"Command: {command}")

    #     return command
