#!/usr/bin/env python3

import re
import os
import sys
import yaml
import boto3
import shutil
import logging
import pathlib
import hashlib
import requests
import subprocess
from base64 import b64decode
from requests.auth import HTTPBasicAuth
from botocore.exceptions import ClientError


def main():
    # Get logging level, set manually when running pipeline
    loglevel = os.environ.get("LOGLEVEL", "INFO").upper()
    if loglevel == "DEBUG":
        logging.basicConfig(
            level=loglevel,
            format="%(levelname)s [%(filename)s:%(lineno)d]: %(message)s",
        )
        logging.debug("Log level set to debug")
    else:
        logging.basicConfig(level=loglevel, format="%(levelname)s: %(message)s")
        logging.info("Log level set to info")

    artifacts_path = os.getenv("ARTIFACT_DIR", ".")
    logging.info(f"Output directory: {artifacts_path}")

    # Read hardening_manifest.yaml file
    downloads = _load_hardening_manifest()

    if not downloads:
        logging.error("INTERNAL ERROR: No hardening_mainfest.yaml file found")
        sys.exit(1)

    if "resources" not in downloads or not downloads["resources"]:
        logging.info(f"No resources in {downloads}")
        sys.exit(0)

    for item in downloads["resources"]:
        download_type = resource_type(item["url"])
        if download_type == "http":
            if "auth" in item:
                if item["auth"]["type"] == "basic":
                    credential_id = item["auth"]["id"].replace("-", "_")
                    password = b64decode(
                        os.getenv("CREDENTIAL_PASSWORD_" + credential_id)
                    )
                    username = b64decode(
                        os.getenv("CREDENTIAL_USERNAME_" + credential_id)
                    )
                    http_download(
                        item["url"],
                        item["filename"],
                        item["validation"]["type"],
                        item["validation"]["value"],
                        artifacts_path,
                        username,
                        password,
                    )
                else:
                    logging.error(
                        "Non Basic auth type provided for HTTP resource, failing"
                    )
                    sys.exit(1)
            else:
                http_download(
                    item["url"],
                    item["filename"],
                    item["validation"]["type"],
                    item["validation"]["value"],
                    artifacts_path,
                )
        if download_type == "docker":
            if "auth" in item:
                if item["auth"]["type"] == "basic":
                    credential_id = item["auth"]["id"].replace("-", "_")
                    password = b64decode(
                        os.getenv("CREDENTIAL_PASSWORD_" + credential_id)
                    ).decode("utf-8")
                    username = b64decode(
                        os.getenv("CREDENTIAL_USERNAME_" + credential_id)
                    ).decode("utf-8")
                    docker_download(
                        item["url"],
                        item["tag"],
                        item["tag"],
                        username,
                        password,
                    )
                else:
                    logging.error(
                        "Non Basic auth type provided for Docker resource, failing"
                    )
                    sys.exit(1)
            else:
                docker_download(item["url"], item["tag"], item["tag"])
        if download_type == "s3":
            if "auth" in item:
                credential_id = item["auth"]["id"].replace("-", "_")
                username = b64decode(
                    os.getenv("S3_ACCESS_KEY_" + credential_id)
                ).decode("utf-8")
                password = b64decode(
                    os.getenv("S3_SECRET_KEY_" + credential_id)
                ).decode("utf-8")
                region = item["auth"]["region"]
                s3_download(
                    item["url"],
                    item["filename"],
                    item["validation"]["type"],
                    item["validation"]["value"],
                    artifacts_path,
                    username,
                    password,
                    region,
                )
            else:
                s3_download(
                    item["url"],
                    item["filename"],
                    item["validation"]["type"],
                    item["validation"]["value"],
                    artifacts_path,
                )


def _load_hardening_manifest():
    """
    Load up the hardening_manifest.yaml file as a dictionary. Search for the file in
    the immediate repo first, if that is not found then search for the generated file.

    If neither are found then return None and let the calling function handle the error.

    """
    artifacts_path = os.environ["ARTIFACT_STORAGE"]
    paths = [
        pathlib.Path("hardening_manifest.yaml"),
        # Check for the generated hardening manifest. This method will be deprecated.
        pathlib.Path(artifacts_path, "preflight", "hardening_manifest.yaml"),
    ]

    for path in paths:
        logging.debug(f"Looking for {path}")
        if path.is_file():
            logging.debug(f"Using {path}")

            if "preflight" in str(path):
                logging.info("Using autogenerated hardening_manifest.yaml")

            with path.open("r") as f:
                return yaml.safe_load(f)
        else:
            logging.debug(f"Couldn't find {path}")
    return None


def resource_type(url):
    check = url
    docker_string = "docker://"
    http_string = "http"
    s3_string = "s3://"
    if docker_string in check:
        return "docker"
    elif http_string in check:
        return "http"
    elif s3_string in check:
        return "s3"
    else:
        return "Error in parsing resource type."


def http_download(
    download_item,
    resource_name,
    validation_type,
    checksum_value,
    artifacts_path,
    username=None,
    password=None,
):
    logging.info(f"===== ARTIFACT: {download_item}")
    # Validate filename doesn't do anything nefarious
    match = re.search(r"^[A-Za-z0-9][^/\x00]*", resource_name)
    if match is None:
        logging.error(
            "Filename is has invalid characters. Filename must start with a letter or a number. Aborting."
        )
        sys.exit(1)

    auth = None
    if username and password:
        auth = HTTPBasicAuth(username, password)

    logging.info(f"Downloading from {download_item}")
    with requests.get(download_item, allow_redirects=True, stream=True, auth=auth) as r:
        r.raw.decode_content = True
        r.raise_for_status()
        with open(artifacts_path + "/external-resources/" + resource_name, "wb") as f:
            shutil.copyfileobj(r.raw, f, length=16 * 1024 * 1024)

    # Calculate SHA256 checksum of downloaded file
    logging.info("Checking file verification type")

    if validation_type != "sha256" and validation_type != "sha512":
        logging.error(f"file verification type not supported: '{validation_type}'")
        sys.exit(1)

    logging.info("Generating checksum")
    checksum_value_from_calc = generate_checksum(
        validation_type, checksum_value, artifacts_path, resource_name
    )

    # Compare checksums
    logging.info(
        f"comparing checksum values: {str(checksum_value_from_calc.hexdigest())} vs {str(checksum_value)}"
    )
    if checksum_value_from_calc.hexdigest() == checksum_value:
        logging.info("Checksum verified")
        logging.info(f"File saved as '{resource_name}'")
    else:
        os.remove(artifacts_path + "/external-resources/" + resource_name)
        logging.error("Checksum failed")
        logging.error("File deleted")
        sys.exit(1)


def s3_download(
    download_item,
    resource_name,
    validation_type,
    checksum_value,
    artifacts_path,
    username=None,
    password=None,
    region=None,
):
    logging.info(f"===== ARTIFACT: {download_item}")

    bucket = download_item.split("s3://")[1].split("/")[0]
    object_name = download_item[len("s3://" + bucket + "/") :]
    # Validate filename doesn't do anything nefarious
    match = re.search(r"^[A-Za-z0-9][^/\x00]*", resource_name)
    if match is None:
        logging.error(
            "Filename is has invalid characters. Filename must start with a letter or a number. Aborting."
        )
        sys.exit(1)

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=username,
        aws_secret_access_key=password,
        region_name=region,
    )

    try:
        s3_client.download_file(
            bucket, object_name, artifacts_path + "/external-resources/" + resource_name
        )
    except ClientError as e:
        logging.error(e)
        sys.exit(1)

    # Calculate SHA256 checksum of downloaded file
    logging.info("Checking file verification type")
    if validation_type != "sha256" and validation_type != "sha512":
        logging.error(f"file verification type not supported: '{validation_type}'")
        sys.exit(1)

    logging.info("Generating checksum")
    checksum_value_from_calc = generate_checksum(
        validation_type, checksum_value, artifacts_path, resource_name
    )

    # Compare checksums
    logging.info(
        f"comparing checksum values: {str(checksum_value_from_calc.hexdigest())} vs {str(checksum_value)}"
    )
    if checksum_value_from_calc.hexdigest() == checksum_value:
        logging.info("Checksum verified")
        logging.info("File saved as '%s'" % resource_name)
    else:
        os.remove(artifacts_path + "/external-resources/" + resource_name)
        logging.error("Checksum failed")
        logging.error("File deleted")
        sys.exit(1)


def generate_checksum(validation_type, checksum_value, artifacts_path, resource_name):
    if validation_type == "sha256":
        sha256_hash = hashlib.sha256()
        with open(artifacts_path + "/external-resources/" + resource_name, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
            return sha256_hash
    elif validation_type == "sha512":
        sha512_hash = hashlib.sha512()
        with open(artifacts_path + "/external-resources/" + resource_name, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha512_hash.update(byte_block)
            return sha512_hash


def docker_download(download_item, tag_value, tar_name, username=None, password=None):
    logging.info(f"===== ARTIFACT: {download_item}")
    image = download_item.split("//")[1]
    tar_name = tar_name.replace("/", "-")
    tar_name = tar_name.replace(":", "-")
    logging.info(f"Pulling {image}")

    pull_cmd = [
        "podman",
        "pull",
        "--storage-driver=vfs",
        "--authfile=/tmp/prod_auth.json",
    ]
    if username and password:
        pull_cmd += ["--creds", f"{username}:{password}"]
    pull_cmd += ["--", image]

    retry = True
    retry_count = 0
    while retry:
        try:
            subprocess.run(pull_cmd, check=True)
            logging.info(f"Tagging image as {tag_value}")
            subprocess.run(
                ["podman", "tag", image, tag_value, "--storage-driver=vfs"], check=True
            )
            logging.info(f"Saving {tag_value} as tar file")
            subprocess.run(
                [
                    "podman",
                    "save",
                    "-o",
                    tar_name + ".tar",
                    tag_value,
                    "--storage-driver=vfs",
                ],
                check=True,
            )
            logging.info("Moving tar file into stage artifacts")
            shutil.copy(
                tar_name + ".tar",
                os.getenv("ARTIFACT_STORAGE") + "/import-artifacts/images/",
            )
            retry = False
        except subprocess.CalledProcessError:
            if retry_count == 2:
                logging.exception(
                    "Docker resource failed to pull, please check hardening_manifest.yaml configuration"
                )
                sys.exit(1)
            else:
                retry_count += 1
                logging.warning(
                    f"Docker resource failed to pull, retrying: {retry_count}/2"
                )


if __name__ == "__main__":
    main()
