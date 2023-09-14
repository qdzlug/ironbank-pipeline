import shutil
from pathlib import Path
from dataclasses import dataclass, field
from pipeline.utils.environment import Environment
from log import log
from oscap import OpenSCAP

SCAP_CONTENT = "scap-content"


@dataclass
class Artifacts:
    """
    A class used to handle OSCAP artifacts and job cleanup.

    ...

    Attributes
    ----------
    directory : Path
        the directory where the artifacts will be saved

    Methods
    -------
    prepare(oscap_version: str)
        Prepares the OSCAP artifacts.
    """

    directory: Path = field(init=False)

    def __post_init__(self) -> None:
        self.directory = Path(Environment().oscap_scans())

    def prepare(self, oscap_version: str) -> None:
        """Prepares the OSCAP artifacts."""
        self._make_directory(self.directory)
        self._remove_scap_content()
        self._save_oscap_version(oscap_version)
        self._move_reports()
        self._save_dynamic_ci_vars()

    def _make_directory(self, path: Path) -> None:
        log.info(f"Initializing directory: {self.directory}")
        path.mkdir(parents=True, exist_ok=True)

    def _remove_scap_content(self) -> None:
        scap_content_dir = SCAP_CONTENT
        try:
            shutil.rmtree(scap_content_dir)
            log.info(f"Directory {scap_content_dir} removed.")
        except OSError as exc:
            log.warning(f"The {scap_content_dir} was not removed: {exc}")

    def _save_oscap_version(self, oscap_version: str) -> None:
        log.info(f"OpenSCAP version: {oscap_version}.")
        oscap_version_file = Path(self.directory) / "oscap-version.txt"
        oscap_version_file.write_text(oscap_version, encoding="utf-8")

    def _move_reports(self) -> None:
        files_to_copy = [
            "report.html",
            "compliance_output_report.xml",
            "compliance_output_report_stigviewer.xml",
        ]
        for file_name in files_to_copy:
            source_file = Path(file_name)
            if source_file.is_file():
                destination_file = Path(self.directory) / file_name
                source_file.replace(destination_file)
                log.info(f"File {source_file} moved to {destination_file}.")
            else:
                log.warning(f"{file_name} does not exist.")

    def _save_dynamic_ci_vars(self) -> None:
        env_path: Path = Path("oscap-compliance.env")
        ci_job_url = Environment().ci_job_url()
        scap_verion = OpenSCAP.get_scap_version()
        cli_version = OpenSCAP.get_cli_version()
        text_to_write = f"""OSCAP_COMPLIANCE_URL={ci_job_url}
SCAP_VERSION={scap_verion}
OSCAP_CLI_VERSION={cli_version}"""
        log.info(OpenSCAP.oscap_version_cli_command())
        env_path.write_text(text_to_write, encoding="utf-8")
