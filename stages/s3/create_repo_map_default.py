#!/usr/bin/python3
import sys
import json
import os
import boto3
import logging
from botocore.exceptions import ClientError
import argparse
import requests


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
        s3_client.download_file(bucket, object_name, "repo_map.json")
    except ClientError as e:
        logging.error(e)
        print("Existing repo_map.json not found, creating new repo_map.json")
        return False
    return True


# Get values generated by process_yaml() in metadata.py
# Currently used to retrieve keywords and tags
def source_values(source_file, key):
    num_vals = 0
    val_list = []
    if os.path.exists(source_file):
        with open(source_file, mode="r", encoding="utf-8") as sf:
            for line in sf:
                val_entry = line.strip()
                val_list.append(val_entry)
                num_vals += 1
        if key == "Keywords":
            print("Number of keywords detected: ", num_vals)
        elif key == "Tags":
            print("Number of tags detected: ", num_vals)
    else:
        logging.info(source_file + " does not exist")
    return val_list


def _get_source_keys_values(source_file):
    """
    Returns the labels from the hardening_manifest.yaml file as dictionary.
    Ignore keywords since IBFE already has an implementation for gathering keywords

    """
    hm_labels = {}
    if os.path.exists(source_file):
        with open(source_file, mode="r", encoding="utf-8") as sf:
            for line in sf:
                key, value = line.rstrip().split("=", 1)
                if key != "mil.dso.ironbank.image.keywords":
                    hm_labels[key] = value
    return hm_labels


def _get_approval_status(source_file):
    if os.path.exists(source_file):
        with open(source_file, mode="r", encoding="utf-8") as sf:
            approval_object = json.load(sf)
    approval_status = approval_object["IMAGE_APPROVAL_STATUS"]
    approval_text = approval_object["IMAGE_APPROVAL_TEXT"]
    return approval_status, approval_text


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
    parser.add_argument("--container_type", help="type of container OS (UBI, distroless, ubuntu, etc")
    args = parser.parse_args()

    object_name = args.target
    container_type = args.containter_type

    existing_repomap = get_repomap(object_name)
    artifact_storage = os.environ["ARTIFACT_STORAGE"]

    keyword_list = source_values(
        f"{artifact_storage}/preflight/keywords.txt", "Keywords"
    )
    tag_list = source_values(f"{artifact_storage}/preflight/tags.txt", "Tags")
    label_dict = _get_source_keys_values(f"{artifact_storage}/preflight/labels.env")

    approval_status, approval_text = _get_approval_status(
        f"{artifact_storage}/lint/image_approval.json"
    )

    # all environment vars used for adding new data to the repo map must have a value set or they will throw a KeyError
    new_data = {
        os.environ["build_number"]: {
            "Anchore_Gates_Results": os.environ["anchore_gates_results"],
            "Summary_Report": os.environ["summary_report"],
            "Build_Number": os.environ["build_number"],
            "Image_Path": os.environ["image_path"],
            "TwistLock_Results": os.environ["twistlock_results"],
            "Image_Manifest": os.environ["image_manifest"],
            "PGP_Signature": os.environ["pgp_signature"],
            "Signature_Name": os.environ["signature_name"],
            "Public_Key": os.environ["public_key"],
            "Image_URL": os.environ["image_url"],
            "Anchore_Security_Results": os.environ["anchore_security_results"],
            "Image_Sha": os.environ["image_sha"],
#            "OpenSCAP_Compliance_Results": os.environ["openscap_compliance_results"],
            "Tar_Name": os.environ["tar_name"],
#            "OpenSCAP_Report": os.environ["openscap_report"],
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
            "Tags": tag_list,
            "Labels": label_dict,
        }
    }

    if container_type != "distroless":
        new_data["build_number"]["OpenSCAP_Report"]=os.environ["openscap_report"],
        new_data["build_number"]["OpenSCAP_Compliance_Results"]=os.environ["openscap_compliance_results"]

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

##CV: Unsure if we can remove the above upload to S3 or if anything else relies on the file, re-reading and posting to IBFE 
#to prevent breaking anything. This can be changed if we are confident nothing downstream consumes or expects 
#repo_map.json. UNIX style processing -- dirty but works
    try:
        with open('repo_map.json', 'r') as j:
            json_data = json.loads(j.read())
    except FileNotFoundError as f_not_found_err:
        logging.error(f"repo_map.json file not found!\n{f_not_found_err}")
    except Exception as e:
        logging.error(f"repo_map.json file was found, but an unhandled error occured\n{e}")
    try:
        requests.post(os.environ["IBFE_API_ENDPOINT"], data = os.environ["IBFE_API_KEY"], json=data[os.environ["build_number"]])
        logging.info("Uploaded container data to IBFE API")
    except requests.exceptions.RequestException as request_e:
        logging.error(f"Error submitting container data to IBFE API\n{request_e}")

##CV: I don't like this and would prefer not to test if variable exists, except to do a thing, else do a different thing. 
# that feels pretty unclean. UNIX style processing above is hacky but not as bad as below
#    try: data
#    except NameError: 
#        try:
#            r = requests.post(os.environ["IBFE_API_ENDPOINT"], data = os.environ["IBFE_API_KEY"], json=new_data)
#            logging.debug(r)
#        except Exception as post_e:
#            logging.error(f"Error sending data to IBFE:\n{post_e}")        
#    else:
#        try:
#            r = requests.post(os.environ["IBFE_API_ENDPOINT"], data = os.environ["IBFE_API_KEY"], json=data)
#            logging.debug(r)
#        except Exception as post_e:
#            logging.error(f"Error sending data to IBFE:\n{post_e}")


if __name__ == "__main__":
    sys.exit(main())
