#!/usr/bin/env python3

import os
import json
import subprocess
import sys
import mimetypes
from pathlib import Path
from base64 import b64decode
import boto3
from botocore.exceptions import ClientError

from ironbank.pipeline.utils.exceptions import GenericSubprocessError

from .utils import logger  # noqa: E402

from ironbank.pipeline.image import Image, ImageFile
from ironbank.pipeline.container_tools.skopeo import Skopeo

log = logger.setup(name="stargate.artifact_push")


class Stargate:
    """
    Stargate upload object

    """

    def __init__(self):
        self.image_dir = os.environ["ARCHIVE_DIR"]
        self.archive_directory_name = f"{os.environ['ARCHIVE_DIR']}-{os.environ['CI_PROJECT_ID']}-{os.environ['CI_PIPELINE_ID']}"
        self.s3_bucket = os.environ["STARGATE_S3_BUCKET"]

    def get_image_labels(self) -> tuple[str, str]:
        """
        output labels from hardening-manifest into dictionary
        """
        labels_env: dict["str", "str"] = {}
        with Path(f"{os.environ['ARTIFACT_STORAGE']}/preflight/labels.env").open("r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                key, value = line.strip().split("=", 1)
                labels_env[key] = value
        image_title = labels_env["org.opencontainers.image.title"]
        image_description = labels_env["org.opencontainers.image.description"]

        return image_title, image_description

    def generate_metadata(
        self, image_dir: str, image_description: str, object_name: str
    ) -> None:
        """
        Creates metadata file for SG ingest
        """
        log.info("Generating SG metadata")
        metadata = {
            "customerID": "ironbank",
            "baseURI": "registry1.dso.mil/ironbank",
            # Image name
            "name": os.environ["IMAGE_NAME"],
            # Image version
            "version": os.environ["IMAGE_VERSION"],
            "includesImage": True,
            # directory where the docker (someday OCI) image dir is located
            "imageDir": image_dir,
            # HM Description field
            "description": image_description,
            # S3 bucket CI Var
            # "destination": os.environ["STARGATE_S3_BUCKET"],
            "destination": None,
        }
        # write out metadata file
        outfile = Path(os.getcwd(), f"{object_name}.metadata")
        internal_metadata_file = Path(os.getcwd(), f"{image_dir}/metadata.json")
        with outfile.open(mode="w") as f:
            json.dump(metadata, f, indent=4)
        with internal_metadata_file.open(mode="w") as f:
            json.dump(metadata, f, indent=4)
        self.sign_archive(outfile)

    def create_image_directory(self, image_title) -> None:
        """
        generates an archive that can be sent to StarGate's S3 bucket for IB
        skopeo copy from registry1 to dir
        skopeo copy docker://registry1.dso.mil/ironbank-staging/redhat/ubi/ubi8@sha256:<shasum> oci:ubi8:<IMAGE_VERSION>

        Returns a tuple of the name of the image dir and image description
        """
        log.info("Creating image directory")
        # create authfile for skopeo to pull from staging project
        staging_auth = (
            b64decode(os.environ["DOCKER_AUTH_CONFIG_STAGING"])
            .decode("utf-8")
            .replace("\n", "")
        )
        auth_data = json.loads(staging_auth)
        with Path("staging-auth.json").open(mode="w") as f:
            json.dump(auth_data, f)

        skopeo = Skopeo(authfile="staging-auth.json")
        src = Image(
            registry=os.environ["REGISTRY_URL_STAGING"],
            name=os.environ["IMAGE_NAME"],
            digest=os.environ["IMAGE_PODMAN_SHA"],
            transport="docker://",
        )
        dest = ImageFile(
            file_path=Path(
                self.image_dir, f"{image_title}:{os.environ['IMAGE_VERSION']}"
            ),
            transport="oci:",
        )
        try:
            skopeo.copy(src, dest, log_cmd=True)
        except GenericSubprocessError:
            log.error("Could not skopeo copy.")
            sys.exit(1)

    def create_archive(self) -> None:
        """
        Tar up the temp dir
        """
        log.info("Creating archive")
        add_cmd = [
            "tar",
            "-czvf",
            f"{self.archive_directory_name}.tar.gz",
            "-C",
            self.image_dir,
            ".",
        ]

        try:
            subprocess.run(
                add_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
                check=True,
            )
        except subprocess.SubprocessError:
            log.exception("Could not tar archive directory.")
            sys.exit(1)
        self.sign_archive(f"{self.archive_directory_name}.tar.gz")

    def sign_archive(self, object_name) -> None:
        """
        GPG signs an archive
        """
        log.info("GPG signing %s", object_name)
        add_cmd = [
            "gpg",
            "--detach-sign",
            "-o",
            f"{object_name}.sig",
            "--armor",
            "--yes",
            "--batch",
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            f"{os.environ['IB_CONTAINER_SIG_KEY_PASSPHRASE']}",
            object_name,
        ]

        try:
            subprocess.run(
                add_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                encoding="utf-8",
                check=True,
            )
        except subprocess.SubprocessError:
            log.exception("Could not gpg sign archive.")
            sys.exit(1)

    def push_artifacts(self, archive_directory_name: str, bucket: str) -> None:
        """
        Boto3 upload of StarGate artifacts
        """
        # Need to upload in the following order - vault.metadata, vault.metadata.sig, vault.tar.gz, vault.tar.gz.sig
        files_to_upload = [
            f"{archive_directory_name}.metadata",
            f"{archive_directory_name}.metadata.sig",
            f"{archive_directory_name}.tar.gz",
            f"{archive_directory_name}.tar.gz.sig",
        ]

        access_key = os.environ["STARGATE_S3_ACCESS_KEY"]
        secret_key = os.environ["STARGATE_S3_SECRET_KEY"]

        filetype = mimetypes.guess_type(archive_directory_name)

        if not filetype[0]:
            # If mimetype is NoneType use default value
            mimetype = "application/octet-stream"
        elif filetype[1] == "gzip":
            # mimetypes returns 'application/x-tar'
            #   but for S3 to properly serve gzip we need to set to the following
            mimetype = "application/x-compressed-tar"
        else:
            mimetype = filetype[0]  # type:ignore

        extra_args = {
            "ContentType": mimetype,
            "ACL": "private",
        }

        log.debug("extra_args for upload: %s", extra_args)

        # Upload the file
        s3_client = boto3.client(
            "s3",
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            region_name="us-gov-west-1",
        )
        try:
            for upload_file in files_to_upload:
                log.info("Uploading file: %s", upload_file)
                s3_client.upload_file(
                    upload_file,
                    bucket,
                    f"{upload_file}",
                    extra_args,
                )
        except ClientError:
            log.error("S3 client error occurred")
