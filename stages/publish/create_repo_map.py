#!/usr/bin/python3
import sys
import json
import os
import argparse



parser = argparse.ArgumentParser(description='repo_map.json creation')
parser.add_argument('--repo_name', help='')
parser.add_argument('--approval_status', help='')
parser.add_argument('--public_key', help='')
parser.add_argument('--image_sha', help='')
parser.add_argument('--image_name', help='')
parser.add_argument('--image_tag', help='')
parser.add_argument('--image_path', help='')
parser.add_argument('--image_url', help='')
parser.add_argument('--build_number', help='')
parser.add_argument('--image_manifest', help='')
parser.add_argument('--manifest_name', help='')
parser.add_argument('--pgp_signature', help='')
parser.add_argument('--signature_name', help='')
parser.add_argument('--version_documentation', help='')
parser.add_argument('--tar_location', help='')
parser.add_argument('--tar_name', help='')
parser.add_argument('--openscap_compliance_results', help='')
parser.add_argument('--openscap_oval_results', help='')
parser.add_argument('--twistlock_results', help='')
parser.add_argument('--anchore_gates_results', help='')
parser.add_argument('--anchore_security_results', help='')
parser.add_argument('--summary_report', help='')
parser.add_argument('--full_report', help='')
parser.add_argument('--openscap_report', help='')
parser.add_argument('--oval_report', help='')
parser.add_argument('--project_license', help='')
parser.add_argument('--project_readme', help='')
parser.add_argument('--job_type', help='')
parser.add_argument('--output_dir', dest='output_dir', help='directory in which to write CSV output', default='./')
args = parser.parse_args()
job_type = args.job_type
repo_name = args.repo_name
approval_status = args.approval_status
public_key = args.public_key
image_sha = args.image_sha
image_name = args.image_name
image_tag = args.image_tag
image_path = args.image_path
image_url = args.image_url
build_number = args.build_number
image_manifest = args.image_manifest
manifest_name = args.manifest_name
pgp_signature = args.pgp_signature
version_documentation = args.version_documentation
tar_location = args.tar_location
tar_name = args.tar_name
openscap_compliance_results = args.openscap_compliance_results
openscap_oval_results = args.openscap_oval_results
twistlock_results = args.twistlock_results
anchore_gates_results = args.anchore_gates_results
anchore_security_results = args.anchore_security_results
summary_report = args.summary_report
full_report = args.full_report
openscap_report = args.openscap_report
oval_report = args.oval_report
project_license = args.project_license
project_readme = args.project_readme
signature_name = args.signature_name
output_dir = args.output_dir

new = {build_number:
        {
        'Anchore_Gates_Results': anchore_gates_results,
        'Summary_Report': summary_report,
        'Build_Number': build_number,
        'Image_Path': image_path,
        'TwistLock_Results': twistlock_results,
        'Image_Manifest': image_manifest,
        'PGP_Signature': pgp_signature,
        'Signature_Name': signature_name,
        'Public_Key': public_key,
        'Image_URL': image_url,
        'Anchore_Security_Results': anchore_security_results,
        'Image_Sha': image_sha,
        'OpenSCAP_Compliance_Results': openscap_compliance_results,
        'Tar_Name': tar_name,
        'OpenSCAP_OVAL_Results': openscap_oval_results,
        'OpenSCAP_Report': openscap_report,
        'Image_Tag': image_tag,
        'Manifest_Name': manifest_name,
        'Approval_Status': approval_status,
        'Image_Name': image_name,
        'Version_Documentation': version_documentation,
        'OVAL_Report': oval_report,
        'PROJECT_FILE': project_license,
        'PROJECT_README': project_readme,
        'Tar_Location': tar_location,
        'Full_Report': full_report,
        'Repo_Name': repo_name
        }
    }

if job_type == "1" :
    with open('repo_map.json') as f:
        data = json.load(f)
    data.update(new)

    with open('repo_map.json', 'w') as f:
        json.dump(data, f, indent=4)
else:
    with open('repo_map.json', 'w') as outfile:
        json.dump(new, outfile, indent=4, sort_keys=True)