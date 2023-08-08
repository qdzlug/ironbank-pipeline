import shutil
from pathlib import Path
from dataclasses import dataclass, field
from envs import Envs
from log import log

@dataclass
class Artifacts():
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
        self.directory = Envs().oscap_scans

    def prepare(self, oscap_version: str) -> None:
        """Prepares the OSCAP artifacts."""
        self._remove_scap_content()
        self._save_oscap_version(oscap_version)
        self._move_reports()
        self._save_job_url()

    def _remove_scap_content(self) -> None:
        scap_content_dir = Envs().scap_content
        scap_content_dir_str: str = scap_content_dir.as_posix()
        try:
            shutil.rmtree(scap_content_dir_str)
            log.info(f"Directory {scap_content_dir_str} removed.")
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

    def _save_job_url(self) -> None:
        env_path: Path = Path("oscap-compliance.env")
        ci_job_url = Envs().ci_job_url
        log.info(ci_job_url)
        env_path.write_text(ci_job_url, encoding="utf-8")
