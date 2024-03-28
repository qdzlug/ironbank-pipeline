#!/usr/bin/env python3

import json
import logging
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import requests
from common.utils import logger
from pipeline.hardening_manifest import HardeningManifest
from pipeline.project import DsopProject
from pipeline.utils import s3upload
from pipeline.utils.decorators import (
    subprocess_error_handler,
)

log: logging.Logger = logger.setup("vat_artifact_post")


def copy_path(src: Path, dest: Path) -> None:
    """Copy source dir or file to destination If dir endswith a '/', copy
    content in directory but not the directory itself."""
    # Path traversal not safe in this function
    assert ".." not in src.as_posix(), "Path traversal not safe in this function"
    if src.is_dir():
        shutil.copytree(src, dest, dirs_exist_ok=True)
    else:
        shutil.copy2(src, dest)


def post_artifact_data_vat(
    published_timestamp: str,
    tar_path: str,
    readme_path: str,
    license_path: str,
    build: dict,
    hardening_manifest: HardeningManifest,
) -> requests.Response:
    """POST to VAT's artifacts endpoint to allow IBFE to start displaying the
    published image data."""
    vat_endpoint = f"{os.environ['VAT_BACKEND_URL']}/internal/import/artifacts"
    # Allows the multiarch pipeline1 to run legacy projects in prod until other teams are ready.
    # args.version ==> This value comes from args.version, which gets it from the Environment var IMAGE_VERSION which is written by the hardening_manifest_validation.py script run.
    if build["PLATFORM"] == "amd64":
        image_tag = f'{hardening_manifest.labels["org.opencontainers.image.version"]}'
    else:
        image_tag = f'{hardening_manifest.labels["org.opencontainers.image.version"]}-{build["PLATFORM"]}'
    post_resp = requests.post(
        vat_endpoint,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {os.environ['VAT_TOKEN']}",
        },
        json={
            "imageName": build["IMAGE_NAME"],
            "tag": image_tag,
            "publishedTimestamp": published_timestamp,
            "readme": readme_path,
            "license": license_path,
            "tar": tar_path,
        },
        timeout=None,
    )
    return post_resp


def main(build: dict) -> None:
    """Upload tar file to s3 and hit VAT endpoint to provide path to tar file
    After this stage finishes, IBFE is able to display new metadata for the
    associated image."""
    dsop_proj: DsopProject = DsopProject()
    hardening_manifest: HardeningManifest = HardeningManifest(
        dsop_proj.hardening_manifest_path
    )
    report_dir: Path = Path("reports/")
    report_dir.mkdir(parents=True, exist_ok=True)

    report_tar_name: str = os.environ["REPORT_TAR_NAME"]
    utc_datetime_now: str = datetime.utcnow().isoformat(
        sep="T", timespec="milliseconds"
    )
    # remove dsop from project_path (e.g. dsop/redhat/ubi/ubi8 becomes redhat/ubi/ubi8)
    image_path: None | str | re.Match[str] = re.match(
        r"^(?:.*dsop\/)(.*)$", dsop_proj.project_path.as_posix()
    )
    assert isinstance(image_path, re.Match), "No match found for image path"
    image_path = image_path.group(1)

    s3_object_path = f"{image_path}/{hardening_manifest.image_tag}-{build['PLATFORM']}/{utc_datetime_now}_{os.environ['CI_PIPELINE_ID']}"
    print(hardening_manifest.image_tag)

    readme_name: str = "README.md"
    license_name: str = "LICENSE"

    license_path: str = f"{s3_object_path}/{readme_name}_not_uploaded"
    readme_path: str = f"{s3_object_path}/{license_name}_not_uploaded"
    tar_path: str = f"{s3_object_path}/{report_tar_name}"

    report_files: list[str] = [
        f"{os.environ['DOCUMENTATION_DIRECTORY']}",
        f"{os.environ['BUILD_DIRECTORY']}",
        f"{os.environ['SCAN_DIRECTORY']}",
        f"{os.environ['SBOM_DIRECTORY']}",
        f"{os.environ['VAT_DIRECTORY']}",
        dsop_proj.hardening_manifest_path.as_posix(),
        readme_name,
        license_name,
    ]
    for file in report_files:
        file_path = Path(file)
        copy_path(file_path, report_dir)

    log.info(os.listdir(report_dir.as_posix()))

    # tar
    subprocess_error_handler("Failed to compress file")(subprocess.run)(
        ["tar", "-zcvf", report_tar_name, report_dir.as_posix()], check=True
    )
    # upload to s3
    s3upload.upload_file(
        file_name=report_tar_name,
        bucket=os.environ["S3_REPORT_BUCKET"],
        object_name=f"{os.environ['BASE_BUCKET_DIRECTORY']}/{tar_path}",
    )

    try:
        post_resp: requests.Response = post_artifact_data_vat(
            published_timestamp=utc_datetime_now,
            tar_path=tar_path,
            readme_path=readme_path,
            license_path=license_path,
            build=build,
            hardening_manifest=hardening_manifest,
        )
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
    potential_platforms = [
        "amd64",
        "arm64",
    ]

    platforms = [
        platform
        for platform in potential_platforms
        if os.path.isfile(
            f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/build.json'
        )
    ]

    for platform in platforms:
        # load platform build.json
        with open(f'{os.environ["ARTIFACT_STORAGE"]}/build/{platform}/build.json', encoding="utf-8") as f:
            build_json = json.load(f)

        main(build_json)
