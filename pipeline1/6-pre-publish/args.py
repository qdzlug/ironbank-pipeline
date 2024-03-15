import os
from datetime import datetime
from pathlib import Path

from pipeline.utils.environment import Environment


class EnvUtil:
    """DCCSCR processing of CVE reports from various sources."""

    def __init__(self, platform) -> None:
        self._timestamp = datetime.utcnow().strftime("%FT%TZ")
        self.platform = platform

    ###
    # Required
    ###

    @property
    def job_id(self) -> str:
        """Pipeline job ID."""
        return Environment().ci_pipeline_id()

    @property
    def timestamp(self) -> str:
        """Timestamp for current pipeline run."""
        return self._timestamp

    @property
    def scan_date(self) -> str:
        """Scan date for pipeline run."""
        return Environment().build_date()

    @property
    def build_date(self) -> str:
        """Build date for pipeline run."""
        return Environment().build_date_to_scan()

    @property
    def commit_hash(self) -> str:
        """Commit hash for container build."""
        commit_sha: str = Environment().commit_sha_to_scan()
        return commit_sha

    @property
    def container(self) -> str:
        """Container VENDOR/PRODUCT/CONTAINER."""
        return Environment().image_name()

    @property
    def version(self) -> str:
        """Container Version from VENDOR/PRODUCT/CONTAINER/VERSION format."""
        return Environment().image_version()

    @property
    def digest(self) -> str:
        """Container Digest as SHA256 Hash."""
        return Environment().digest_to_scan()

    @property
    def twistlock(self) -> Path:
        """Location of the twistlock JSON scan file."""
        twistlock_path: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/twistlock/{self.platform}/twistlock_cve.json"
        return Path(twistlock_path)

    @property
    def anchore_sec(self) -> Path:
        """Location of the anchore_security.json scan file."""
        anchore_sec_path: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/anchore/{self.platform}/anchore_security.json"
        return Path(anchore_sec_path)

    @property
    def anchore_gates(self) -> Path:
        """Location of the anchore_gates.json scan file."""
        anchore_gates_path: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/anchore/{self.platform}/anchore_gates.json"
        return Path(anchore_gates_path)

    @property
    def comp_link(self) -> str:
        """Link to openscap compliance reports directory."""
        return Environment().oscap_compliance_url()

    ###
    # Optional
    ###

    @property
    def api_url(self) -> str:
        """Url for API POST."""
        backend_url = Environment().vat_backend_url()
        api_url = f"{backend_url}/internal/import/scan"
        return api_url

    @property
    def oscap(self) -> Path:
        """Location of the oscap scan XML file."""
        oscap_path: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/openscap/{self.platform}/compliance_output_report.xml"
        return Path(oscap_path)

    @property
    def parent(self) -> str:
        """Parent VENDOR/PRODUCT/CONTAINER."""
        return Environment().base_image()

    @property
    def parent_version(self) -> str:
        """Parent Version from VENDOR/PRODUCT/CONTAINER/VERSION format."""
        return Environment().base_tag()

    @property
    def repo_link(self) -> str:
        """Link to container repository."""
        return Environment().ci_project_url()

    @property
    def use_json(self) -> str:
        """Whether to use predefined payload."""
        return Environment().use_json_for_vat()
