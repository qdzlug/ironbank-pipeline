import subprocess
import urllib.request
import urllib.error
import zipfile
import json
import re
import xml.etree.ElementTree as etree
from dataclasses import dataclass, field
from pathlib import Path
from log import log

from pipeline.utils.envs import Envs
from pipeline.utils.decorators import subprocess_error_handler

VERSION_PATH: Path = Path("stages/scanning/oscap-version.json")
SCAP_GUIDE_ZIP_PATH: Path = Path("scap-security-guide.zip")
SCAP_CONTENT_DIR: Path = Path("scap-content")
BASE_URL: str = "https://github.com/ComplianceAsCode/content/releases/download"
NO_VERSION_ERROR: str = "Unable to get OpenSCAP version from oscap-version.json. Version is required to run scan."
PATTERN = r"/security/oval/suse\.linux\.enterprise\.15\.xml"
REPLACEMENT = "/security/oval/suse.linux.enterprise.server.15-patch.xml"
LIMITED_IMAGE: str = "sle15-bci-container"
SCAP_URL_TEMPLATE: str = (
    "https://access.redhat.com/security/data/oval/v2/RHEL{}/rhel-{}.oval.xml.bz2"
)
CHECK_ID_TEMPLATE_PATH: str = (
    "scap_org.open-scap_cref_security-data-oval-com.redhat.rhsa-RHEL{}.xml.bz2"
)
XML_NAMESPACE = {
    "ds": "http://scap.nist.gov/schema/scap/source/1.2",
    "xlink": "http://www.w3.org/1999/xlink",
}


@dataclass
class OpenSCAP:
    """
    A class to manage OpenSCAP configuration and resources.

    ...

    Attributes
    ----------
    version : str
        The OpenSCAP version. If the version is not set, a ValueError will be raised when initializing an instance of this class.

    Methods
    -------
    download_content():
        Downloads and extracts the SCAP content.

    Raises
    ------
    ValueError
        If the OpenSCAP version is not found.
    """

    version: str = field(init=False)

    def __post_init__(self) -> None:
        try:
            self.version = self._get_openscap_version()
        except FileNotFoundError as exc:
            error_message = "OpenSCAP version file not found. With OpenSCAP version, the scan is not possible."
            log.error(f"{error_message}: {exc}")
            raise ValueError(NO_VERSION_ERROR) from exc
        except ValueError as exc:
            raise ValueError(NO_VERSION_ERROR) from exc

    def _get_openscap_version(self) -> str:
        version_file_path: Path = Path(Envs().pipeline_repo_dir) / VERSION_PATH
        version: str = self._read_file_version(version_file_path)
        if not version:
            raise ValueError("Version not found in the version file.")
        return version

    @classmethod
    def get_scap_version(cls):
        """Get the SCAP version used by the CLI tool"""
        result = cls.oscap_version_cli_command()
        scap_version_pattern = r"SCAP Version: ([\d.]+)"
        scap_version_match = re.search(scap_version_pattern, result)
        scap_version = scap_version_match.group(1) if scap_version_match else None
        return scap_version

    @classmethod
    def get_cli_version(cls):
        """Get the version of the CLI tool"""
        result = cls.oscap_version_cli_command()
        oscap_version_pattern = r"OpenSCAP command line tool \(oscap\) ([\d.]+)"
        oscap_version_match = re.search(oscap_version_pattern, result)
        oscap_version = oscap_version_match.group(1) if oscap_version_match else None
        return oscap_version

    @classmethod
    @subprocess_error_handler("Failed to get version")
    def oscap_version_cli_command(cls):
        """Wraps the 'oscap --version' command"""
        result = subprocess.run(
            ["oscap", "--version"], stdout=subprocess.PIPE, check=True
        )
        return result

    def _read_file_version(self, version_file_path: Path) -> str:
        with version_file_path.open(encoding="utf-8") as file:
            data = json.load(file)
            version: str = data["version"].lstrip("v")
        return version

    def _get_download_url(self) -> str:
        scap_url: str = Envs().scap_url
        # pylint does not understand ci_var decorator
        # pylint: disable=comparison-with-callable
        if scap_url != "":
            return scap_url
        return f"{BASE_URL}/v{self.version}/scap-security-guide-{self.version}.zip"

    def _download_file(self, url: str, scap_zip_path: Path) -> None:
        try:
            SCAP_CONTENT_DIR.mkdir(parents=True, exist_ok=True)
            log.info(f"Downloading content from {url}.")
            urllib.request.urlretrieve(url, scap_zip_path)
            log.info("Download completed.")
        except (urllib.error.HTTPError, urllib.error.URLError) as exc:
            log.error(f"Error occurred while downloading the SCAP content: {exc}")
            raise IOError("Failed to download content.") from exc

    def _extract_zip(self, scap_zip_path: Path) -> None:
        try:
            log.info(f"Extracting content to {SCAP_CONTENT_DIR}.")
            with zipfile.ZipFile(scap_zip_path, "r") as zip_ref:
                zip_ref.extractall(SCAP_CONTENT_DIR)
            log.info("Extraction complete.")
        except zipfile.BadZipFile as exc:
            log.error(f"The file is not a zip file or it is corrupt: {exc}")
            raise IOError(
                "Failed to extract zip file: File is not a zip file or it is corrupt."
            ) from exc
        except zipfile.LargeZipFile as exc:
            log.error(f"The file size is too large: {exc}")
            raise IOError(
                "Failed to extract zip file: File size is too large."
            ) from exc

    def _limit_scanning(self, security_guide_path: Path) -> None:
        try:
            security_guide_path = SCAP_CONTENT_DIR / security_guide_path
            # Check if file exists
            if not security_guide_path.is_file():
                log.error(f"File {security_guide_path} does not exist.")
                raise IOError("Failed to limit scanning: File does not exist.")

            # Read the file
            data = security_guide_path.read_text()

            # Replace the string
            data = re.sub(PATTERN, REPLACEMENT, data)

            # Write the file
            security_guide_path.write_text(data)
        except FileNotFoundError as exc:
            log.error(f"File {security_guide_path} not found.")
            raise IOError("Failed to limit scanning: File not found.") from exc
        except PermissionError as exc:
            log.error(f"No permission to read or write to {security_guide_path}.")
            raise IOError(
                "Failed to limit scanning: No permission to read or write to file."
            ) from exc

    # Modularize this further
    def _fix_ubi_oval_url(self, image_type: str, security_guide_path: Path) -> None:
        """Handle ubi image oval link pointing to v1."""
        try:
            ubi_version = image_type.split("-", maxsplit=1)[0][-1]
            full_path: Path = SCAP_CONTENT_DIR / security_guide_path
            root = etree.parse(full_path)
            checks = root.find("ds:data-stream/ds:checks", XML_NAMESPACE)
            if not checks:
                raise ValueError("The checks element was not found in the XML.")
            for check in checks.findall("ds:component-ref", XML_NAMESPACE):
                if check.attrib["id"] == CHECK_ID_TEMPLATE_PATH.format(ubi_version):
                    check.set(
                        f"{{{XML_NAMESPACE['xlink']}}}href",
                        SCAP_URL_TEMPLATE.format(ubi_version, ubi_version),
                    )
            root.write(full_path)
        except ValueError as exc:
            log.error(f"Error updating the image oval link: {exc}")
            raise IOError(
                "Failed to fix UBI oval URL: Error updating the image oval link."
            ) from exc
        except etree.ParseError as exc:
            log.error(
                f"Error parsing XML file at {SCAP_CONTENT_DIR / security_guide_path}: {exc}"
            )
            raise IOError(
                "Failed to fix UBI oval URL: Error parsing XML file."
            ) from exc

    def download_content(self, image_type: str, security_guide_path: Path) -> None:
        """Downloads and extracts the Security Content Automation Protocol
        (SCAP) content.

        This method downloads a zip file of the SCAP content from a specified URL and
        extracts the zip file. If the image type is "sle15-bci-container", the method limits
        the scanning to a particular pattern. For an image type that includes "ubi",
        the method fixes the oval URL to point to a particular version.

        Parameters
        ----------
        image_type : str
            The type of the image. If it's a "sle15-bci-container", the scanning will be limited
            to a particular pattern. If it includes "ubi", the oval URL will be fixed
            to point to a particular version.
        security_guide_path : pathlib.Path
            The path of the security guide used for limiting the scanning or fixing the oval URL.

        Raises
        ------
        IOError
            If there is an error during the download of the SCAP content or during
            the extraction of the downloaded zip file or during the limitation of scanning
            or during the fixing of the oval URL.
        """
        scap_zip_path: Path = SCAP_CONTENT_DIR / SCAP_GUIDE_ZIP_PATH

        download_url = self._get_download_url()

        self._download_file(download_url, scap_zip_path)
        self._extract_zip(scap_zip_path)
        if image_type == LIMITED_IMAGE:
            self._limit_scanning(security_guide_path)
        if "ubi" in image_type:
            self._fix_ubi_oval_url(image_type, security_guide_path)
