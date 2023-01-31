#!/usr/bin/env python3

from datetime import datetime
import os
from pathlib import Path
import re
import subprocess
import sys
import shutil
import requests
from ironbank.pipeline.project import DsopProject
from ironbank.pipeline.hardening_manifest import HardeningManifest
from ironbank.pipeline.utils import s3upload

from ironbank.pipeline.utils import logger


log = logger.setup("vat_artifact_post")


def post_artifact_data_vat(tar_path: Path):
    """
    POST to VAT's artifacts endpoint to allow IBFE to start displaying the published image data
    """
    vat_endpoint = (
        f"{os.environ['VAT_BACKEND_SERVER_ADDRESS']}/internal/import/artifacts"
    )
    post_resp = requests.post(
        vat_endpoint,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['CI_JOB_JWT_V2']}",
        },
        json={
            "imageName": os.environ["IMAGE_NAME"],
            "tag": os.environ["IMAGE_VERSION"],
            "publishedTimestamp": os.environ["directory_date"],
            "readme": "NONE",
            "license": "NONE",
            "tar": tar_path,
        },
        timeout=None,
    )
    return post_resp


def main():
    if "pipeline-test-project" in os.environ["CI_PROJECT_DIR"]:
        log.info(
            "Skipping publish. Cannot publish when working with pipeline test projects master branch..."
        )
        sys.exit(0)

    dsop_proj = DsopProject()
    hm = HardeningManifest(dsop_proj.hardening_manifest_path)

    report_dir = Path("reports")
    report_dir.mkdir(parents=True, exist_ok=True)

    artifact_storage = os.environ["ARTIFACT_STORAGE"]
    report_tar_name = os.environ["REPORT_TAR_NAME"]
    utc_datetime_now = datetime.utcnow().isoformat(sep="T", timespec="milliseconds")
    image_path = re.match(r"^(?:.*dsop\/)(.*)$", dsop_proj.project_path)

    tar_path = f"{image_path}/{hm.image_tag}/{utc_datetime_now}_{os.environ['CI_PIPELINE_ID']}/{report_tar_name}"

    report_files = [
        f"{os.environ['DOCUMENTATION_DIRECTORY']}/reports/*",
        f"{os.environ['BUILD_DIRECTORY']}/access_log",
        f"{os.environ['SCAN_DIRECTORY']}/",
        f"{os.environ['SBOM_DIRECTORY']}/",
        f"{artifact_storage}/vat/vat_response.json",
        "README.md",
        "LICENSE",
    ]
    for file in report_files:
        shutil.move(Path(file), report_dir)

    log.info(os.listdir(report_dir))

    # tar
    subprocess.run(["tar", "-zcvf", report_tar_name, report_dir.as_posix()], check=True)
    # upload to s3
    s3upload.upload_file(
        file_name=report_tar_name,
        bucket=os.environ["S3_REPORT_BUCKET"],
        object_name=f"{os.environ['BASE_BUCKET_DIRECTORY']}/{tar_path}",
    )

    try:
        post_resp = post_artifact_data_vat(tar_path=tar_path)
        post_resp.raise_for_status()
        log.info("Uploaded container data to VAT API")
    except requests.exceptions.RequestException as req_exc:
        log.error("Error submitting container data to VAT API")
        if isinstance(req_exc, requests.exceptions.Timeout):
            log.exception("Unable to reach the VAT API, TIMEOUT.")
        if isinstance(req_exc, requests.exceptions.HTTPError):
            log.error("Got HTTP %s", post_resp.status_code)
            log.error("VAT HTTP error")
        sys.exit(1)


if __name__ == "__main__":
    main()
