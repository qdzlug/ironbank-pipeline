import os
from datetime import datetime


class Args:
    """DCCSCR processing of CVE reports from various sources."""

    def __init__(self) -> None:
        self._timestamp = datetime.utcnow().strftime("%FT%TZ")

    ###
    # Required
    ###

    @property
    def job_id(self) -> str:
        """Pipeline job ID."""
        return os.environ.get("CI_PIPELINE_ID", "")

    @property
    def timestamp(self) -> str:
        """Timestamp for current pipeline run."""
        return self._timestamp

    @property
    def scan_date(self) -> str:
        """Scan date for pipeline run."""
        return os.environ.get("BUILD_DATE", "")

    @property
    def build_date(self) -> str:
        """Build date for pipeline run."""
        return os.environ.get("BUILD_DATE_TO_SCAN", "")

    @property
    def commit_hash(self) -> str:
        """Commit hash for container build."""
        return os.environ.get("COMMIT_SHA_TO_SCAN", "")

    @property
    def container(self) -> str:
        """Container VENDOR/PRODUCT/CONTAINER."""
        return os.environ.get("IMAGE_NAME", "")

    @property
    def version(self) -> str:
        """Container Version from VENDOR/PRODUCT/CONTAINER/VERSION format."""
        return os.environ.get("IMAGE_VERSION", "")

    @property
    def digest(self) -> str:
        """Container Digest as SHA256 Hash."""
        return os.environ.get("DIGEST_TO_SCAN", "")

    @property
    def twistlock(self) -> str:
        """Location of the twistlock JSON scan file."""
        return f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/twistlock/twistlock_cve.json"

    @property
    def anchore_sec(self) -> str:
        """Location of the anchore_security.json scan file."""
        return f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/anchore/anchore_security.json"

    @property
    def anchore_gates(self) -> str:
        """Location of the anchore_gates.json scan file."""
        return f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/anchore/anchore_gates.json"

    @property
    def comp_link(self) -> str:
        """Link to openscap compliance reports directory."""
        return os.environ.get("OSCAP_COMPLIANCE_URL", "")

    ###
    # Optional
    ###

    @property
    def api_url(self) -> str:
        """Url for API POST."""
        return (
            f"{os.environ.get('VAT_BACKEND_URL')}/internal/import/scan"
            if os.environ.get("VAT_BACKEND_URL")
            else "http://localhost:4000/internal/import/scan"
        )

    @property
    def oscap(self) -> str:
        """Location of the oscap scan XML file."""
        return f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/openscap/compliance_output_report.xml"

    @property
    def parent(self) -> str:
        """Parent VENDOR/PRODUCT/CONTAINER."""
        return os.environ.get("BASE_IMAGE", "")

    @property
    def parent_version(self) -> str:
        """Parent Version from VENDOR/PRODUCT/CONTAINER/VERSION format."""
        return os.environ.get("BASE_TAG", "")

    @property
    def repo_link(self) -> str:
        """Link to container repository."""
        return os.environ.get("CI_PROJECT_URL", "")

    @property
    def use_json(self) -> bool:
        """Dump payload for API to out.json file."""
        return bool(os.environ.get("USE_JSON", False))
