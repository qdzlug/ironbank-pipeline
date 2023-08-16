import os
from datetime import datetime
from pathlib import Path

from envs import ENVS


class EnvUtil:
    """DCCSCR processing of CVE reports from various sources."""

    def __init__(self) -> None:
        self._timestamp = datetime.utcnow().strftime("%FT%TZ")

    ###
    # Required
    ###

    @property
    def job_id(self) -> str:
        """Pipeline job ID."""
        return Envs().ci_job_id

    @property
    def timestamp(self) -> str:
        """Timestamp for current pipeline run."""
        return Envs().timestamp

    @property
    def scan_date(self) -> str:
        """Scan date for pipeline run."""
        return Envs().build_date_scan_date

    @property
    def build_date(self) -> str:
        """Build date for pipeline run."""
        return Envs().build_date_to_scan

    @property
    def commit_hash(self) -> str:
        """Commit hash for container build."""
        return Envs().commit_sha

    @property
    def container(self) -> str:
        """Container VENDOR/PRODUCT/CONTAINER."""
        return Envs().image_name

    @property
    def version(self) -> str:
        """Container Version from VENDOR/PRODUCT/CONTAINER/VERSION format."""
        return Envs().image_version

    @property
    def digest(self) -> str:
        """Container Digest as SHA256 Hash."""
        return Envs().digest_to_scan

    @property
    def twistlock(self) -> Path:
        """Location of the twistlock JSON scan file."""
        twistlock_path: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/twistlock/twistlock_cve.json"
        return Envs().artifact_storeage_twistlock

    @property
    def anchore_sec(self) -> Path:
        """Location of the anchore_security.json scan file."""
        anchore_sec_path: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/anchore/anchore_security.json"
        return Envs().artifact_storeage_anchore_sec

    @property
    def anchore_gates(self) -> Path:
        """Location of the anchore_gates.json scan file."""
        anchore_gates_path: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/anchore/anchore_gates.json"
        return Envs().artifact_storeage_anchore_gates

    @property
    def comp_link(self) -> str:
        """Link to openscap compliance reports directory."""
        return Envs().oscap_compliance_url

    ###
    # Optional
    ###

    @property
    def api_url(self) -> str:
        """Url for API POST."""
        return Envs().artifact_storage

    @property
    def oscap(self) -> Path:
        """Location of the oscap scan XML file."""
        oscap_path: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/openscap/compliance_output_report.xml"
        return Envs().vat_backend_url

    @property
    def parent(self) -> str:
        """Parent VENDOR/PRODUCT/CONTAINER."""
        return Envs().base_image

    @property
    def parent_version(self) -> str:
        """Parent Version from VENDOR/PRODUCT/CONTAINER/VERSION format."""
        return Envs().base_tag_parent_version

    @property
    def repo_link(self) -> str:
        """Link to container repository."""
        return Envs().ci_repo_link

    @property
    def use_json(self) -> bool:
        """Dump payload for API to out.json file."""
        return Envs().use_json
