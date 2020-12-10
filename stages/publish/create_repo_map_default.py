#!/usr/bin/python3
import sys
import json
import os
import shlex
import subprocess
import boto3
import logging
from botocore.exceptions import ClientError
import argparse
import logging


def get_repomap(object_name, bucket="ironbank-pipeline-artifacts"):

    access_key = os.environ["S3_ACCESS_KEY"]
    secret_key = os.environ["S3_SECRET_KEY"]

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-gov-west-1",
    )

    print(object_name)
    try:
        response = s3_client.download_file(bucket, object_name, "repo_map.json")
    except ClientError as e:
        logging.error(e)
        print("Existing repo_map.json not found, creating new repo_map.json")
        return False
    return True


def source_values(source_file, key):
    num_vals = 0
    val_list = []
    with open(source_file, mode="r", encoding="utf-8") as sf:
        for line in sf:
            val_entry = line.strip()
            val_list.append(val_entry)
            num_vals += 1
    if key == "Keywords":
        print("Number of keywords detected: ", num_vals)
    elif key == "Tags":
        print("Number of tags detected: ", num_vals)
    return val_list


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

    parser = argparse.ArgumentParser(description="Downloads target from s3")
    parser.add_argument("--target", help="File to upload")
    args = parser.parse_args()

    object_name = args.target

    existing_repomap = get_repomap(object_name)
    artifact_storage = os.environ.get("ARTIFACT_STORAGE")
    keyword_list = source_values(
        f"{artifact_storage}/preflight/keywords.txt", "Keywords"
    )
    tag_list = source_values(f"{artifact_storage}/preflight/tags.txt", "Tags")

    new_data = {
        os.environ.get("build_number"): {
            "Anchore_Gates_Results": os.environ.get("anchore_gates_results"),
            "Summary_Report": os.environ.get("summary_report"),
            "Build_Number": os.environ.get("build_number"),
            "Image_Path": os.environ.get("image_path"),
            "TwistLock_Results": os.environ.get("twistlock_results"),
            "Image_Manifest": os.environ.get("image_manifest"),
            "PGP_Signature": os.environ.get("pgp_signature"),
            "Signature_Name": os.environ.get("signature_name"),
            "Public_Key": os.environ.get("public_key"),
            "Image_URL": os.environ.get("image_url"),
            "Anchore_Security_Results": os.environ.get("anchore_security_results"),
            "Image_Sha": os.environ.get("image_sha"),
            "OpenSCAP_Compliance_Results": os.environ.get(
                "openscap_compliance_results"
            ),
            "Tar_Name": os.environ.get("tar_name"),
            "OpenSCAP_OVAL_Results": os.environ.get("openscap_oval_results"),
            "OpenSCAP_Report": os.environ.get("openscap_report"),
            "Image_Tag": os.environ.get("image_tag"),
            "Manifest_Name": os.environ.get("manifest_name"),
            "Approval_Status": os.environ.get("approval_status"),
            "Image_Name": os.environ.get("image_name"),
            "Version_Documentation": os.environ.get("version_documentation"),
            "OVAL_Report": os.environ.get("oval_report"),
            "PROJECT_FILE": os.environ.get("project_license"),
            "PROJECT_README": os.environ.get("project_readme"),
            "Tar_Location": os.environ.get("tar_location"),
            "Full_Report": os.environ.get("full_report"),
            "Repo_Name": os.environ.get("repo_name"),
            "Keywords": keyword_list,
            "Tags": tags_list,
        }
    }

    if existing_repomap:
        with open("repo_map.json") as f:
            data = json.load(f)
        data.update(new_data)

        with open("repo_map.json", "w") as f:
            json.dump(data, f, indent=4)
    else:
        with open("repo_map.json", "w") as outfile:
            json.dump(new_data, outfile, indent=4, sort_keys=True)


if __name__ == "__main__":
    sys.exit(main())
