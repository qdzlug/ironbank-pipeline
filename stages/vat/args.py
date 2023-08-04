from dataclasses import dataclass
from datetime import datetime
import os


@dataclass
class Args:
    """DCCSCR processing of CVE reports from various sources."""

    ###
    # Required
    ###

    # Pipeline job ID
    job_id: str = os.environ.get("CI_PIPELINE_ID", "")

    # Timestamp for current pipeline run
    timestamp: str = datetime.utcnow().strftime("%FT%TZ")

    # Scan date for pipeline run
    scan_date: str = os.environ.get("BUILD_DATE", "")

    # Build date for pipeline run
    build_date: str = os.environ.get("BUILD_DATE_TO_SCAN", "")

    # Commit hash for container build
    commit_hash: str = os.environ.get("COMMIT_SHA_TO_SCAN", "")

    # Container VENDOR/PRODUCT/CONTAINER
    container: str = os.environ.get("IMAGE_NAME", "")

    # Container Version from VENDOR/PRODUCT/CONTAINER/VERSION format
    version: str = os.environ.get("IMAGE_VERSION", "")

    # Container Digest as SHA256 Hash
    digest: str = os.environ.get("DIGEST_TO_SCAN", "")

    # Location of the twistlock JSON scan file
    twistlock: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/twistlock/twistlock_cve.json"

    # Location of the anchore_security.json scan file
    anchore_sec: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/anchore/anchore_security.json"

    # Location of the anchore_gates.json scan file
    anchore_gates: str = (
        f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/anchore/anchore_gates.json"
    )

    # More weird bash
    # Link to openscap compliance reports directory
    comp_link: str = os.environ.get("OSCAP_COMPLIANCE_URL:-''", "")

    ###
    # Optional
    ###

    # Url for API POST
    api_url: str = (
        f"{os.environ.get('VAT_BACKEND_URL')}/internal/import/scan"
        if os.environ.get("VAT_BACKEND_URL")
        else "http://localhost:4000/internal/import/scan"
    )

    # Location of the oscap scan XML file
    oscap: str = f"{os.environ.get('ARTIFACT_STORAGE')}/scan-results/openscap/compliance_output_report.xml"

    # Parent VENDOR/PRODUCT/CONTAINER
    parent: str = os.environ.get("BASE_IMAGE", "")

    # Parent Version from VENDOR/PRODUCT/CONTAINER/VERSION format
    parent_version: str = os.environ.get("BASE_TAG", "")

    # Link to container repository
    repo_link: str = os.environ.get("CI_PROJECT_URL", "")

    # Dump payload for API to out.json file
    use_json: bool = bool(os.environ.get("USE_JSON", False))
