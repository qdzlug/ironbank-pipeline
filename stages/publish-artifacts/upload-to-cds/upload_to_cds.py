#!/usr/bin/env python3

import logging
import os
import subprocess

from common.utils import logger
from pipeline.hardening_manifest import HardeningManifest
from pipeline.project import DsopProject
from pipeline.utils import s3upload
from pipeline.utils.decorators import stack_trace_handler, subprocess_error_handler

log: logging.Logger = logger.setup("upload_to_cds_s3_bucket")


@subprocess_error_handler("Failed to pull image from harbor.")
def pull_image(image_name, image_tag, url, artifact_dir) -> None:
    """Use skopeo to copy the docker image from harbor."""

    image = f"docker://{url}/{image_name}:{image_tag}"
    dest = f"oci:{artifact_dir}:{image_tag}"
    auth = "--authfile=" + os.environ["DOCKER_AUTH_FILE_PULL"]

    log.info(f"Copying {image}")

    subprocess.run(["skopeo", "copy", auth, image, dest], check=True)


@stack_trace_handler
@subprocess_error_handler("Failed upload to cds s3 bucket")
def main() -> None:
    """Pulls the signed image from Harbor, converts it to a tar.gz file, and
    pushes it to the CDS S3 bucket."""

    cds_source_bucket = os.environ.get("CDS_SOURCE_BUCKET")
    registry_url = os.environ["REGISTRY_PUBLISH_URL"]
    image_name = os.environ.get("IMAGE_NAME")
    artifact_dir = os.environ.get("ARTIFACT_DIR")
    project = DsopProject()
    hardening_manifest = HardeningManifest(project.hardening_manifest_path)

    image_tag = hardening_manifest.image_tags[0]

    # Pull the signed docker image that was pushed to harbor in the harbor job
    pull_image(image_name, image_tag, registry_url, artifact_dir)

    # create tar file
    tar_file = f"{image_name}:{image_tag}.tar.gz"
    cmd = [
        "tar",
        "--warning=no-file-changed",
        "-czvf",
        f"{artifact_dir}/tmp.tar.gz",
        "-C",
        f"{artifact_dir}",
        ".",
    ]
    log.info("Creating the tar file")
    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        log.info(e)

    # Push that tar.gz to the CDS S3 bucket
    log.info("Uploading tar file to CDS S3 bucket")
    s3upload.upload_file(
        file_name=f"{artifact_dir}/tmp.tar.gz",
        bucket=cds_source_bucket,
        object_name=f"containers/{tar_file}",
    )

    log.info(f"{tar_file} was uploaded to {cds_source_bucket}")


if __name__ == "__main__":
    main()
