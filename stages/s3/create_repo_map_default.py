#!/usr/bin/python3
import sys
import json
import os
import boto3
import logging
from botocore.exceptions import ClientError
import argparse

sys.path.append(
    os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "scripts/modules"
    )
)

from hardening_manifest import (
    source_values,
    get_source_keys_values,
    get_approval_status,
)  # noqa E402


def get_repomap(object_name, bucket="ironbank-pipeline-artifacts") -> bool:

    access_key = os.environ["S3_ACCESS_KEY"]
    secret_key = os.environ["S3_SECRET_KEY"]

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-gov-west-1",
    )

    logging.info(object_name)
    try:
        s3_client.download_file(bucket, object_name, "repo_map.json")
    except ClientError as e:
        logging.error(e)
        logging.info("Existing repo_map.json not found, creating new repo_map.json")
        return False
    return True


def main() -> None:
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

    parser = argparse.ArgumentParser(description="Downloads target from s3")
    parser.add_argument("--target", help="File to upload")
    args = parser.parse_args()

    object_name = args.target

    existing_repomap = get_repomap(object_name)
    artifact_storage = os.environ["ARTIFACT_STORAGE"]

    keyword_list = source_values(
        f"{artifact_storage}/preflight/keywords.txt", "keywords"
    )
    tag_list = source_values(f"{artifact_storage}/preflight/tags.txt", "tags")
    label_dict = get_source_keys_values(f"{artifact_storage}/preflight/labels.env")

    approval_status, approval_text = get_approval_status(
        f"{artifact_storage}/lint/image_approval.json"
    )

    digest = os.environ["IMAGE_PODMAN_SHA"].replace("sha256:", "")
    # all environment vars used for adding new data to the repo map must have a value set or they will throw a KeyError
    new_data = {
        os.environ["build_number"]: {
            "Anchore_Gates_Results": os.environ["anchore_gates_results"],
            "Summary_Report": os.environ["summary_report"],
            "Build_Number": os.environ["build_number"],
            "Image_Path": os.environ["image_path"],
            "TwistLock_Results": os.environ["twistlock_results"],
            "Image_Manifest": os.environ["image_manifest"],
            "Public_Key": os.environ["public_key"],
            "Anchore_Security_Results": os.environ["anchore_security_results"],
            "Image_Sha": os.environ["image_sha"],
            "OpenSCAP_Compliance_Results": os.environ.get("openscap_compliance_results")
            if not os.environ.get("DISTROLESS")
            else None,
            "Tar_Name": os.environ["tar_name"],
            "OpenSCAP_Report": os.environ.get("openscap_report")
            if not os.environ.get("DISTROLESS")
            else None,
            "Image_Tag": os.environ["image_tag"],
            "Manifest_Name": os.environ["manifest_name"],
            "Approval_Status": approval_status,
            "Approval_Text": approval_text,
            "Image_Name": os.environ["image_name"],
            "Version_Documentation": os.environ["version_documentation"],
            "PROJECT_FILE": os.environ["project_license"],
            "PROJECT_README": os.environ["project_readme"],
            "Tar_Location": os.environ["tar_location"],
            "Full_Report": os.environ["full_report"],
            "Repo_Name": os.environ["repo_name"],
            "Keywords": keyword_list,
            "digest": digest,
            "Tags": tag_list,
            "Labels": label_dict,
        }
    }

    logging.debug(f"repo_map data:\n{new_data}")

    if existing_repomap:
        with open("repo_map.json", "r+") as f:
            data = json.load(f)
            data.update(new_data)
            f.seek(0, 0)
            f.truncate()
            json.dump(data, f, indent=4)
    else:
        with open("repo_map.json", "w") as outfile:
            json.dump(new_data, outfile, indent=4, sort_keys=True)


if __name__ == "__main__":
    main()
