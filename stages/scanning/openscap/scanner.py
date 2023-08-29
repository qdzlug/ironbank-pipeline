import subprocess
from dataclasses import dataclass
from typing import List
from image import Image
from log import log
from pipeline.utils.decorators import subprocess_error_handler
from pipeline.utils.exceptions import GenericSubprocessError

SCAP_CONTENT = "scap-content"


@dataclass
class Scanner:
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

    def scan(self) -> None:
        """Perform OpenSCAP scan on the provided Image object.

        Raises
        ------
        GenericSubprocessError
            If the scan fails.
        """
        try:
            self._run_subprocess()
            log.info("Command completed successfully.")
        except GenericSubprocessError as exc:
            log.error(f"The scan failed: {exc}")
            raise

    @subprocess_error_handler("Scan failed.")
    def _run_subprocess(self) -> subprocess.CompletedProcess:
        image = self._image
        docker_image_path: str = image.path.as_posix()
        profile: str = image.profile
        scap_content: str = SCAP_CONTENT
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

        log.info(f"Executing: {command}")

        result = subprocess.run(
            command,
            stderr=subprocess.PIPE, check=False)
        
        if result.returncode == 0:
            log.info("All rules passed.")
        elif result.returncode == 1:
            log.error(f"An error occurred during evaluation: {result.stderr}")
            raise GenericSubprocessError("An error occurred during evaluation.")
        elif result.returncode ==2:
            log.warning(f"At least one rule with either fail or unknown result: {result.stderr}")

        return result
