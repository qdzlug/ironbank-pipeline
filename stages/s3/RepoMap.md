# Repo Map Description

## Background

The repo_map.json file was created to provide information about each build of master branch pipelines. These files are uploaded to S3, and when subsequent builds are performed, are updated with the latest build information. The initial design of the Iron Bank Front End (IBFE) website, read the data in these files. This is now no longer the case, but the files are still generated for the time being.

## Data Description

### Repo Map Key-Value Pairs and Supporting Vars

IMAGE_PATH is a variable created in the upload-to-s3.sh script
directory date is the UTC datetime of when this script is run

```sh
IMAGE_PATH=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')
```

IMAGE_NAME and IMAGE_VERSION are created in the metadata.py scipt. The image name is the name value in the Hardening Manifest (HM) The image version is the first value provided in the array of tags in a project's HM

```py <!-- metadata.py -->
with (artifact_dir / "variables.env").open("w") as f:
    f.write(f"IMAGE_NAME={content['name']}\n")
    f.write(f"IMAGE_VERSION={content['tags'][0]}\n")
```

Setup vars in the repo_map_vars.sh file

```sh <!-- repo_map_vars.sh -->
S3_HTML_LINK="https://s3-us-gov-west-1.amazonaws.com/${S3_REPORT_BUCKET}/${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMAGE_VERSION}"
directory_date=$(date --utc '+%FT%T.%3N')
public_key=$(<"${IB_CONTAINER_GPG_PUBKEY}")
```

| Key                         | Source                                                              | Notes                                                                                         |
| --------------------------- | ------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| S3_HTML_LINK                | See above                                                           | This uses the IMAGE_PATH var from the upload-to-s3.sh script                                  |
| Anchore_Gates_Results       | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/anchore_gates.csv` |
| Summary_Report              |
| Build_Number                |
| Image_Path                  | `${REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_VERSION}`                    | This is a duplicate key. This value is not the same as the value used in the S3_HTML_LINK var |
| TwistLock_Results           |
| Image_Manifest              |
| Public_Key                  |
| Anchore_Security_Results    |
| Image_Sha                   |
| OpenSCAP_Compliance_Results |
| Tar_Name                    |
| OpenSCAP_Report             |
| Image_Tag                   |
| Manifest_Name               |
| Approval_Status             |
| Approval_Text               |
| Image_Name                  |
| Version_Documentation       |
| PROJECT_FILE                |
| PROJECT_README              |
| Tar_Location                |
| Full_Report                 |
| Repo_Name                   |
| Keywords                    |
| digest                      |
| Tags                        |
| Labels                      |

### Data Structure

```py <!-- create_repo_map_default.py -->
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
```

### Output

Using Anchore Enterprise build info as an example

```json <!-- repo_map.json extract -->
{
    "549779": {
        "Anchore_Gates_Results": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/csvs/anchore_gates.csv",
        "Summary_Report": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/csvs/summary.csv",
        "Build_Number": "549779",
        "Image_Path": "registry1.dso.mil/ironbank/anchore/enterprise/enterprise:3.2.0",
        "TwistLock_Results": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/csvs/tl.csv",
        "Image_Manifest": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/manifest.json",
        "Public_Key": "-----BEGIN PGP PUBLIC KEY BLOCK-----...
        -----END PGP PUBLIC KEY BLOCK-----",
        "Anchore_Security_Results": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/csvs/anchore_security.csv",
        "Image_Sha": "sha256:9110723ec9adc766306f2a30807302de27c58c66bc08c315214dcc671d53f9c4",
        "OpenSCAP_Compliance_Results": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/csvs/oscap.csv",
        "Tar_Name": "enterprise-3.2.0-reports-signature.tar.gz",
        "OpenSCAP_Report": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/openscap/report.html",
        "Image_Tag": "3.2.0",
        "Manifest_Name": "manifest.json",
        "Approval_Status": "approved",
        "Approval_Text": "Auto Approval derived from previous version anchore/enterprise/enterprise:3.1.1",
        "Image_Name": "enterprise",
        "Version_Documentation": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/documentation.json",
        "PROJECT_FILE": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/LICENSE",
        "PROJECT_README": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/README.md",
        "Tar_Location": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/enterprise-3.2.0-reports-signature.tar.gz",
        "Full_Report": "https://s3-us-gov-west-1.amazonaws.com/ironbank-pipeline-artifacts/container-scan-reports/anchore/enterprise/enterprise/3.2.0/2021-10-31T23:49:04.891_549779/reports/csvs/all_scans.xlsx",
        "Repo_Name": "anchore/enterprise/enterprise",
        "Keywords": [],
        "digest": "8dc49a06d499038d0ef03cbc2143abcc011d242b011dc828024bf0597ace3007",
        "Tags": [
            "3.2.0",
            "latest"
        ],
        "Labels": {
            "org.opencontainers.image.title": "enterprise",
            "org.opencontainers.image.description": "container image scanning service for policy-based security, best-practice and compliance enforcement",
            "org.opencontainers.image.licenses": "Anchore License",
            "org.opencontainers.image.url": "https://docs.anchore.com/current/docs/",
            "org.opencontainers.image.vendor": "Anchore",
            "org.opencontainers.image.version": "3.2.0",
            "mil.dso.ironbank.image.type": "commercial",
            "mil.dso.ironbank.product.name": "anchore/enterprise"
        }
    }
}
```
