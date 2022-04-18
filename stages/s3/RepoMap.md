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

IMAGE_NAME and IMAGE_VERSION are created in the metadata.py script. The image name is the name value in the Hardening Manifest (HM) The image version is the first value provided in the array of tags in a project's HM.

<!-- metadata.py -->

```py
with (artifact_dir / "variables.env").open("w") as f:
    f.write(f"IMAGE_NAME={content['name']}\n")
    f.write(f"IMAGE_VERSION={content['tags'][0]}\n")
```

Setup vars in the repo_map_vars.sh file

<!-- repo_map_vars.sh -->

```sh
S3_HTML_LINK="https://s3-us-gov-west-1.amazonaws.com/${S3_REPORT_BUCKET}/${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMAGE_VERSION}"
directory_date=$(date --utc '+%FT%T.%3N')
public_key=$(<"${IB_CONTAINER_GPG_PUBKEY}")
```

Variables set in upload-to-s3 yaml file

<!-- upload-to-s3.yaml -->

```yaml
variables:
  IMAGE_FILE: "${CI_PROJECT_NAME}-${IMAGE_VERSION}"
  SCAN_DIRECTORY: "${ARTIFACT_STORAGE}/scan-results"
  DOCUMENTATION_DIRECTORY: "${ARTIFACT_STORAGE}/documentation"
  BUILD_DIRECTORY: "${ARTIFACT_STORAGE}/build"
  BASE_BUCKET_DIRECTORY: testing/container-scan-reports
  DOCUMENTATION_FILENAME: documentation
  ARTIFACT_DIR: ${ARTIFACT_STORAGE}/documentation
  REPORT_TAR_NAME: ${CI_PROJECT_NAME}-${IMAGE_VERSION}-reports-signature.tar.gz
```

| Key                         | Source                                                                                               | Notes                                                                                                    |
| --------------------------- | ---------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------- |
| S3_HTML_LINK                | See above                                                                                            | This uses the IMAGE_PATH var from the upload-to-s3.sh script                                             |
| Anchore_Gates_Results       | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/anchore_gates.csv`                                  | The gates CSV is the compliance scan results                                                             |
| Summary_Report              | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/summary.csv`                                        | Contains the finding count totals for each scan type                                                     |
| Build_Number                | `${CI_PIPELINE_ID}`                                                                                  | Built in GitLab CI variable. Pipeline IDs are unique across all Repo1 pipelines                          |
| Image_Path                  | `${REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_VERSION}`                                                     | This is a duplicate key. This value is not the same as the value used in the S3_HTML_LINK var            |
| TwistLock_Results           | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/tl.csv`                                             |                                                                                                          |
| Image_Manifest              | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/manifest.json`                                           | GPG info no longer relevant                                                                              |
| Public_Key                  | see above                                                                                            | No longer used                                                                                           |
| Anchore_Security_Results    | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/anchore_security.csv`                               | Anchore CVE findings results                                                                             |
| Image_Sha                   | `IMAGE_ID=sha256:$(podman inspect --storage-driver=vfs "${IMAGE_REGISTRY_REPO}" --format '{{.Id}}')` | Created in the build stage of the pipeline. This is the image ID shasum                                  |
| OpenSCAP_Compliance_Results | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/oscap.csv`                                          | Set in job yaml variables                                                                                |
| Tar_Name                    | `${REPORT_TAR_NAME}`                                                                                 | Created in S3 job's yaml variables, see above. This is no longer relevant                                |
| OpenSCAP_Report             | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/openscap/report.html`                                    | HTML report output from OpenSCAP job                                                                     |
| Image_Tag                   | `${IMAGE_VERSION}`                                                                                   | Set in metadata.py script. See above                                                                     |
| Manifest_Name               | `manifest.json`                                                                                      | This value is hard coded                                                                                 |
| Approval_Status             | `lint/image_approval.json` and parsed by grabbing the `IMAGE_APPROVAL_STATUS` value                  | This is parsed in the `create_repo_map_default.py` script, in the `_get_approval_status` function        |
| Approval_Text               | `lint/image_approval.json` and parsed by grabbing the `IMAGE_APPROVAL_TEXT` value                    | This is parsed in the `create_repo_map_default.py` script, in the `_get_approval_status` function        |
| Image_Name                  | `${CI_PROJECT_NAME}`                                                                                 | This value may conflict with the `Repo_Name` value                                                       |
| Version_Documentation       | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${DOCUMENTATION_FILENAME}.json`                          | `DOCUMENTATION_FILENAME` is hard coded to `documentation`                                                |
| PROJECT_FILE                | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_LICENSE}`                                      | Hard coded to `LICENSE`                                                                                  |
| PROJECT_README              | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_README}`                                       | Hard coded to `README.md`                                                                                |
| Tar_Location                | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${REPORT_TAR_NAME}`                                      | See above for `REPORT_TAR_NAME` variable creation                                                        |
| Full_Report                 | `${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/all_scans.xlsx`                                     | Excel sheet created by combining individual CSV files                                                    |
| Repo_Name                   | `${IMAGE_NAME}`                                                                                      | `IMAGE_NAME` set in `metadata.py` script, see above. This value may conflict with the `Image_Name` value |
| Keywords                    | `lint/keywords.txt` and parsed by script in `create_repo_map_default.py`                             | uses `source_values` function to parse                                                                   |
| digest                      | `os.environ["IMAGE_PODMAN_SHA"].replace("sha256:", "")`                                              | `IMAGE_PODMAN_SHA` variable is created in the build stage                                                |
| Tags                        | `lint/tags.txt` and parsed by script in `create_repo_map_default.py`                                 | uses `source_values` function to parse                                                                   |
| Labels                      | `lint/labels.env` and parsed by script in `create_repo_map_default.py`                               | uses `_get_source_keys_values` function to parse                                                         |

### Data Structure

<!-- create_repo_map_default.py -->

```py
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

<!-- repo_map.json extract -->

```json
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
