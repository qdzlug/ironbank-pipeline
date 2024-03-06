<!-- markdownlint-disable-file MD033 -->

# S3 Publish

This job in the pipeline uploads the metadata and scan data for the container in the `repo_map.json` file to S3 and the IBFE API directly via HTTP POST.

## Dependencies & Conditions

This job relies on the following stages completing successfully

- load-scripts
- lint
- build
- create-sbom-x86
- scan-logic
- scanning
- generate-documentation
- vat

This job only runs on the following branches:

- master
- development

## Variables required for this job

- SCAN_DIRECTORY
- DOCUMENTATION_DIRECTORY
- BUILD_DIRECTORY
- SBOM_DIRECTORY
- VAT_DIRECTORY
- BASE_BUCKET_DIRECTORY
- DOCUMENTATION_FILENAME
- ARTIFACT_DIR
- REPORT_TAR_NAME
- KUBERNETES_SERVICE_ACCOUNT_OVERWRITE

## Executed Scripts/Binaries

- ${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/upload-to-s3-run.sh

## Code Walkthroughs

## S3 Upload - Overview

Uploads repo_map.json to S3

High Level Overview of Actions

1. Populate variable `filetype

## Purpose

Directly update IBFE so they don't have to read in the repo_map.json from S3 and remove that dependency. There is a (slight) delay in data entering S3 currently because we have to write the `repo_map.json` to S3 and then they have to read it at some point after that; the delta is the delay. This way, in the pipeline run, we add or update the information directly in IBFE which writes it to the IBFE DB. This is a much more efficient process.

## Code - In Depth

### Functions

- main
- load_data

### Required Modules

- os
- pathlib
- logging
- requests
- json
- sys

### Main

```py
if __name__ == "__main__":
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

    parser = argparse.ArgumentParser(
        description="Uploading various reports and files to DCCSCR S3"
    )

    parser.add_argument("--filename", help="File to upload")
    parser.add_argument("--bucket", help="Bucket to upload to")
    parser.add_argument("--dest", help="S3 object path")
    args = parser.parse_args()

    file_name = args.filename
    bucket = args.bucket
    object_name = args.dest

    upload_file(file_name, bucket, object_name)
```

- set loglevel and output what it is set to
- set up argument parser to get filename, bucket, and destination (s3 object path)
- set variables based on input passed to the script
- call `upload_file` function and pass variables `file_name` `bucket` and `object_name`

### upload_file

```py
def upload_file(file_name, bucket, object_name=None):
    """Upload a file to an S3 bucket

    :param file_name: File to upload
    :param bucket: Bucket to upload to
    :param object_name: S3 object name. If not specified then file_name is used
    :return: True if file was uploaded, else False
    """

    access_key = os.environ["S3_ACCESS_KEY"]
    secret_key = os.environ["S3_SECRET_KEY"]

    filetype = mimetypes.guess_type(file_name)

    if not filetype[0]:
        # If mimetype is NoneType use default value
        mimetype = "application/octet-stream"
    elif filetype[1] == "gzip":
        # mimetypes returns 'application/x-tar'
        #   but for S3 to properly serve gzip we need to set to the following
        mimetype = "application/x-compressed-tar"
    else:
        mimetype = filetype[0]
```

- set access key
- set mimetype based on the guessed type of file.
  - if the first element in `filetype` does not exist (no type information), set equal to `application/octet-stream`
  - OR the second element is equal to `gzip` set equal to `application/x-tar`
  - OR set equal to the first element in variable `filetype`

```py
    # TODO: Add signature
    extra_args = {
        "ContentType": mimetype,
        "ACL": "private",
    }

    logging.debug(f"extra_args for {file_name}: {extra_args}")
    # If S3 object_name was not specified, use file_name
    if object_name is None:
        object_name = file_name

    # Upload the file
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-gov-west-1",
    )
    try:
        s3_client.upload_file(file_name, bucket, object_name, extra_args)
    except ClientError:
        logging.error("S3 client error occurred")
        return False
    return True
```

- set the mimetype of the file by setting `ContentType` to the variable `mimetype`, which was set above. This sets the metadata in S3 to say what type of file is being stored
- instantiate S3 client
- try to upload the file to the `bucket` at path `object_name` with the metadata stored in `extra_args`
  - if an exception of type `ClientError` is raised, log it, return boolean `False` to the main function
  - If upload succeeds return boolean `True` to the main function

## Upload to S3 Run - Overview

This script is run by Gitlab because it is in the yaml configuration file as the action when the publish-artifacts stage launches

Overview of Actions:

1. check what branch is running
2. install necessary modules into container
3. run `create_repo_map_default.py`
4. move some files
5. run `s3_upload.py`
6. run `ibfe_api_post.py`

## Purpose

this is essentially the entrypoint for the container when this job runs. It collects some information and preps the container to run the python scripts, and moves output files. This is the "launcher" for all of the actions that are undertaken in this job of the pipeline

## Code - In Depth

### Functions

None

### Required Modules

None

### Code

#### script

```bash
#!/bin/bash
set -Eeuo pipefail
if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project' && [ "${CI_COMMIT_BRANCH}" == "master" ]; then
  echo "Skipping publish. Cannot publish when working with pipeline test projects master branch..."
  exit 0
fi
```

Quit if project is `pipeline-test-project` and the running branch is `master`

```bash
mkdir -p "${ARTIFACT_DIR}"

# pip install boto3 ushlex
if [ "${CI_COMMIT_BRANCH}" == "master" ]; then
  BASE_BUCKET_DIRECTORY="container-scan-reports"
fi

IMAGE_PATH=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')

# Files are guaranteed to exist by the preflight checks
PROJECT_README="README.md"
PROJECT_LICENSE="LICENSE"
VAT_FINDINGS="${ARTIFACT_STORAGE}/lint/vat_api_findings.json"

# shellcheck source=./stages/publish-artifacts/s3/repo_map_vars.sh
source "${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/repo_map_vars.sh"
```

Make necessary directories, set variables, and install necessary python3 modules (boto3, ushlex)

```bash
python3 "${PIPELINE_REPO_DIR}"/stages/publish-artifacts/s3/create_repo_map_default.py --target "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/repo_map.json"
mkdir reports
cp -r "${DOCUMENTATION_DIRECTORY}"/reports/* reports/
cp -r "${SCAN_DIRECTORY}"/* reports/

cp "${PROJECT_LICENSE}" "${PROJECT_README}" reports/
```

Run `create_repo_map_default.py` script and copy reports to local `reports` directory from where this script is running

```bash
if [ -f "${VAT_FINDINGS}" ]; then
cp "${VAT_FINDINGS}" reports/
  python3 "${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/s3_upload.py" --file "${VAT_FINDINGS}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMAGE_VERSION}/${REMOTE_REPORT_DIRECTORY}/${VAT_FINDINGS}"
else
echo "WARNING: ${VAT_FINDINGS} does not exist, not copying into report"
fi

# Debug

ls reports

tar -zcvf "${REPORT_TAR_NAME}" reports

python3 "${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/s3_upload.py" --file repo_map.json --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/repo_map.json"
while IFS= read -r -d '' file; do
object_path="${file#"$ARTIFACT_STORAGE/documentation/"}"
python3 "${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/s3_upload.py" --file "$file" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMAGE_VERSION}/${REMOTE_DOCUMENTATION_DIRECTORY}/$object_path"
done < <(find "${DOCUMENTATION_DIRECTORY}" -type f -print0)

while IFS= read -r -d '' file; do
report_name=$(echo "$file" | rev | cut -d/ -f1-2 | rev)
echo "$file"
  python3 "${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/s3_upload.py" --file "$file" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMAGE_VERSION}/${REMOTE_REPORT_DIRECTORY}/$report_name"
done < <(find "${SCAN_DIRECTORY}" -type f -print0)

python3 "${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/s3_upload.py" --file "${PROJECT_README}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMAGE_VERSION}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_README}"
python3 "${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/s3_upload.py" --file "${PROJECT_LICENSE}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMAGE_VERSION}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_LICENSE}"
python3 "${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/s3_upload.py" --file "${REPORT_TAR_NAME}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMAGE_VERSION}/${REMOTE_REPORT_DIRECTORY}/${REPORT_TAR_NAME}"
```

Check that `reports` directory exists, create tarball of the directory. Upload files to S3 `$ARTIFACT_STORAGE/documentation`

```bash
# Only call IBFE POST API if pipeline is running on "master" branch

if [ "${CI_COMMIT_BRANCH}" == "master" ]; then
python3 "${PIPELINE_REPO_DIR}/stages/publish-artifacts/s3/ibfe_api_post.py"
fi

```

Post results to IBFE API, if running on master branch

## Create Repo Map - Overview

This module has a few functions and overall uploads the json file, that eventually populates IBFE metadata, to S3. It is written in Python, last tested with Python 3.8

High Level Overview of Actions

1. download the repo_map file from S3, if it exists
2. fill a dictionary object with data from the current build. Values may differ based on the type of base container (distroless or not distroless)
3. if the repo_map.json file exists with old data, update the dictionary structure and write the updated data to the file. Otherwise, if no repo_map.json file exists or is blank flush the data to it, write the file, and close the handle.

## Purpose

This will create metadata, documentation, and scan data in IBFE for all approved containers. It adds paths to all of the security scans in the front end. In addition, it pushes all of the json and csv files so they are available, it pushes metadata about the container, of which some is displayed for customers.

## Code - In Depth

### Functions

- main
- get_repomap
- source_values

### Required Modules

- sys
- json
- os
- boto3
- logging
- ClientError (from botocore.exceptions)
- argparse

#### Main

##### Inputs

None

##### Code

```py
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
```

Set logging and output some information if set to DEBUG (most verbose) or INFO (high verbosity)

```py
    parser = argparse.ArgumentParser(description="Downloads target from s3")
    parser.add_argument("--target", help="File to upload")
    args = parser.parse_args()
    object_name = args.target
```

Add arguments to script to allow these to be passed on execution via CI/CD or command line execution

```py
    existing_repomap = get_repomap(object_name)
    artifact_storage = os.environ["ARTIFACT_STORAGE"]
```

Set Boolean `existing_repomap` to the returned value from `get_repomap` function (Result can be `True` or `False`)

```py
    keyword_list = source_values(
        f"{artifact_storage}/lint/keywords.txt", "Keywords"
    )
    tag_list = source_values(f"{artifact_storage}/lint/tags.txt", "Tags")
    label_dict = _get_source_keys_values(f"{artifact_storage}/lint/labels.env")

    approval_status, approval_text = _get_approval_status(
        f"{artifact_storage}/lint/image_approval.json"
    )
    digest = os.environ["IMAGE_PODMAN_SHA"].replace("sha256:", "")
```

- Set List `keyword_list` to the returned values from function `source_values`, passing in the keywords.txt as the `source_file` from the preflight stage.
- Set `tag_list` to the returned values from function `source_values`, passing in the tags.txt as the `source_file` from the preflight stage.
- Set String variables `approval_status` and `approval_text` from `_get_approval_status`.
- Set String `digest`, which is the checksum of the built container, to the value in the pipeline value `IMAGE_PODMAN_SHA`, and replace the beginning of tha value "sha256:" with nothing (remove that string from the beginning of the digest to only get the checksum)

```py
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
            "OpenSCAP_Compliance_Results": os.environ.get("openscap_compliance_results")
            if not os.environ.get("SKIP_OPENSCAP")
            else None,
            "Tar_Name": os.environ["tar_name"],
            "OpenSCAP_Report": os.environ.get("openscap_report")
            if not os.environ.get("SKIP_OPENSCAP")
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

Fill dictionary `new_data` with a top level element equal to the pipeline build number. then fill out the rest of the structure with variables from the current build. Conditionally add openscap compliance results file link if it is not a distroless container build. the rest of these values should be self explanatory.

```py
logging.debug(f"repo_map data:\n{new_data}")

    if existing_repomap:
        with Path("repo_map.json").open("r+") as f:
            data = json.load(f)
            data.update(new_data)
            f.seek(0, 0)
            f.truncate()
            json.dump(data, f, indent=4)
    else:
        with Path("repo_map.json").open("w") as outfile:
            json.dump(new_data, outfile, indent=4, sort_keys=True)
```

if debug logging is active, log to file the data in the dictionary `new_data` created above. if there is an existing repo_map.json file downloaded form S3 in the `get_repo_map` function, update the data in the file with the contents of `new_data`, otherwise write `new_data` to repo_map.json

#### Get Repo Map

##### Inputs

object_name, <span style="color:aqua"><b>String</b></span>  
bucket_name, <span style="color:aqua"><b>String</b></span> [pre-set]

##### Code

```py
def get_repomap(object_name, bucket="ironbank-pipeline-artifacts"):

    access_key = os.environ["S3_ACCESS_KEY"]
    secret_key = os.environ["S3_SECRET_KEY"]

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        region_name="us-gov-west-1",
    )

```

Get access and secret key from secrets held in Gitlab CI/CD variable pipeline. Instantiate s3 client.

```py
    print(object_name)
    try:
        s3_client.download_file(bucket, object_name, "repo_map.json")
    except ClientError as e:
        logging.error(e)
        print("Existing repo_map.json not found, creating new repo_map.json")
        return False
    return True

```

Print the String `object_name`. Download the file repo_map.json and catch any error with exception ID `ClientError`; Print this error, return to the calling function `False` (file does not exist) otherwise, if successful return `True` to the calling function (file exists).

#### Source Values

##### Inputs

source_file, <span style="color:aqua"><b>String</b></span>  
key, <span style="color:aqua"><b>String</b></span>

##### Code

```py
    num_vals = 0
    val_list = []
    if os.path.exists(source_file):
        with Path(source_file).open("r") as sf:
            for line in sf:
                val_entry = line.strip()
                val_list.append(val_entry)
                num_vals += 1

```

Set a couple local variables; If the source file exists, open the file and parse each line, append the results to dictionary name `val_list`

```py
        if key == "Keywords":
            print("Number of keywords detected: ", num_vals)
        elif key == "Tags":
            print("Number of tags detected: ", num_vals)
        else:
            logging.info(source_file + " does not exist")
        return val_list

```

Print some information about keywords or tags and return the dictionary `val_list` back to the main function

#### Get Source Keys Values

##### Inputs

source_file, <span style="color:aqua"><b>String</b></span>

##### Code

```py
def _get_source_keys_values(source_file):
    hm_labels = {}
    if os.path.exists(source_file):
        with Path(source_file).open("r") as sf:
            for line in sf:
                key, value = line.rstrip().split("=", 1)
                if key != "mil.dso.ironbank.image.keywords":
                    hm_labels[key] = value
    return hm_labels

```

Returns the labels from the hardening_manifest.yaml file as dictionary. Ignore keywords since IBFE already has an implementation for gathering keywords

#### Get Approval Status

##### Inputs

source_file, <span style="color:aqua"><b>String</b></span>

##### Code

```py
def _get_approval_status(source_file):
    if os.path.exists(source_file):
        with Path(source_file).open("r") as sf:
            approval_object = json.load(sf)
    approval_status = approval_object["IMAGE_APPROVAL_STATUS"]
    approval_text = approval_object["IMAGE_APPROVAL_TEXT"]
    return approval_status, approval_text

```

This is created in the lint stage via an API call to VAT. If `source_file` exists, open and set JSON object to the data from `source_file`.

## Post to IBFE - Overview

This module sends container data directly to the IBFE (Iron Bank Front End) API

High Level Overview of Actions

1. Populate variable `data` with contents of `repo_map.json`
2. Use an HTTP POST to the API endpoint to send the data directly to IBFE.

## Purpose

Directly update IBFE so they don't have to read in the repo_map.json from S3 and remove that dependency. There is a (slight) delay in data entering S3 currently because we have to write the `repo_map.json` to S3 and then they have to read it at some point after that; the delta is the delay. This way, in the pipeline run, we add or update the information directly in IBFE which writes it to the IBFE DB. This is a much more efficient process.

## Code - In Depth

### Functions

- main
- load_data

### Required Modules

- os
- pathlib
- logging
- requests
- json
- sys

### Main

#### Inputs

None

#### Code

```py
def main():
    if os.environ["CI_COMMIT_BRANCH"] == "master":
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
        new_data = load_data()
        try:
            post_resp = requests.post(
                os.environ["IBFE_API_ENDPOINT"],
                headers={"Authorization": os.environ["IBFE_API_KEY"]},
                json=new_data,
            )
            post_resp.raise_for_status()
            logging.info("Uploaded container data to IBFE API")
        except requests.exceptions.Timeout:
            logging.exception("Unable to reach the IBFE API, TIMEOUT.")
            sys.exit(1)
        except requests.exceptions.HTTPError:
            logging.error(f"Got HTTP {post_resp.status_code}")
            logging.exception("HTTP error")
            sys.exit(1)
        except requests.exceptions.RequestException:
            logging.exception("Error submitting container data to IBFE API")
            sys.exit(1)
        except Exception:
            logging.exception("Unhandled exception")
            sys.exit(1)
    else:
        logging.debug("Skipping use of ibfe api build endpoint")
```

If current pipeline run is on `master` branch. Set up logging, set fields and formatting, and output to the log what logging level is active. If the pipeline is run on any other branch, just log that we are going to skip performing all of the actions in this file.

call the `load_data` function and set `new_data` equal to the returned values. Use a try/except statement and use an HTTP POST json request to the IBFE API. Raise any exceptions that occur in the modules used such as `requests` which is the underling python module used to make the API call. Catch the following errors:

- generic timeout from module `requests`, this means the API did not respond in the default configured time
- ANY HTTP error codes received from the IBFE API
- any other exceptions raised by the requests module
- ANY other exception

Log a specific string to indicate the error that occurred. In the case of an HTTP error code, log the specific code received. If any error is raised, immediately exit with error code "1", after logging.
