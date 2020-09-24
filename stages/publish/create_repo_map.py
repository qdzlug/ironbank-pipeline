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

def get_repomap(object_name, bucket = 'ironbank-pipeline-artifacts'):

    access_key = os.environ["S3_ACCESS_KEY"]
    secret_key = os.environ["S3_SECRET_KEY"]

    s3_client = boto3.client('s3',
                         aws_access_key_id=access_key,
                         aws_secret_access_key=secret_key,
                         region_name='us-gov-west-1'
                      ) 

    print(object_name)
    try:
        response = s3_client.download_file(bucket, object_name, 'repo_map.json')
    except ClientError as e:
        logging.error(e)
        print("Existing repo_map.json not found, creating new repo_map.json")
        return False
    return True

def main():

    parser = argparse.ArgumentParser(description = 'Downloads target from s3')
    parser.add_argument('--target',   help='File to upload')
    args = parser.parse_args()

    object_name = args.target

    existing_repomap = get_repomap(object_name)

    command = shlex.split("bash -c 'source repo_map_vars.sh && env'")
    proc = subprocess.Popen(command, stdout = subprocess.PIPE)
    for line in proc.stdout:
        (key, _, value) = line.decode().partition("=")
        os.environ[key] = value.strip('\n')

    new_data = {os.environ['build_number']:
        {
        'Anchore_Gates_Results': os.environ['anchore_gates_results'],
        'Summary_Report': os.environ['summary_report'],
        'Build_Number': os.environ['build_number'],
        'Image_Path': os.environ['image_path'],
        'TwistLock_Results': os.environ['twistlock_results'],
        'Image_Manifest': os.environ['image_manifest'],
        'PGP_Signature': os.environ['pgp_signature'],
        'Signature_Name': os.environ['signature_name'],
        'Public_Key': os.environ['public_key'],
        'Image_URL': os.environ['image_url'],
        'Anchore_Security_Results': os.environ['anchore_security_results'],
        'Image_Sha': os.environ['image_sha'],
        'OpenSCAP_Compliance_Results': os.environ['openscap_compliance_results'],
        'Tar_Name': os.environ['tar_name'],
        'OpenSCAP_OVAL_Results': os.environ['openscap_oval_results'],
        'OpenSCAP_Report': os.environ['openscap_report'],
        'Image_Tag': os.environ['image_tag'],
        'Manifest_Name': os.environ['manifest_name'],
        'Approval_Status': os.environ['approval_status'],
        'Image_Name': os.environ['image_name'],
        'Version_Documentation': os.environ['version_documentation'],
        'OVAL_Report': os.environ['oval_report'],
        'PROJECT_FILE': os.environ['project_license'],
        'PROJECT_README': os.environ['project_readme'],
        'Tar_Location': os.environ['tar_location'],
        'Full_Report': os.environ['full_report'],
        'Repo_Name': os.environ['repo_name']
        }
    }



    if existing_repomap:
        with open('repo_map.json') as f:
            data = json.load(f)
        data.update(new_data)

        with open('repo_map.json', 'w') as f:
            json.dump(data, f, indent=4)
    else:
        with open('repo_map.json', 'w') as outfile:
            json.dump(new_data, outfile, indent=4, sort_keys=True)

if __name__ == "__main__":
    sys.exit(main())
