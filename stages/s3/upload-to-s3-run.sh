#!/bin/bash
set -Eeuo pipefail
if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project' && [ "${CI_COMMIT_BRANCH}" == "master" ]; then
  echo "Skipping publish. Cannot publish when working with pipeline test projects master branch..."
  exit 0
fi

mkdir -p "${ARTIFACT_DIR}"


IMAGE_PATH=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')

# Files are guaranteed to exist by the lint checks

PROJECT_README="README.md"
PROJECT_LICENSE="LICENSE"

VAT_FINDINGS="${ARTIFACT_STORAGE}/lint/vat_api_findings.json"
VAT_RESPONSE="${ARTIFACT_STORAGE}/vat/vat_response.json"

mkdir reports
cp hardening_manifest.yaml reports/
cp "${BUILD_DIRECTORY}"/access_log reports/
cp -r "${DOCUMENTATION_DIRECTORY}"/reports/* reports/
cp -r "${SCAN_DIRECTORY}"/* reports/

cp "${PROJECT_LICENSE}" "${PROJECT_README}" reports/
mv "${SBOM_DIRECTORY}"/* reports/

if [ -f "${VAT_FINDINGS}" ]; then
  cp "${VAT_FINDINGS}" reports/
else
  echo "WARNING: ${VAT_FINDINGS} does not exist, not copying into report"
fi

cp "${VAT_RESPONSE}" reports/

export TAR_PATH_SHORT="${IMAGE_PATH}/${IMAGE_VERSION}/$(date --utc '+%FT%T.%3N')_${CI_PIPELINE_ID}/${REPORT_TAR_NAME}"

# Debug
ls reports

tar -zcvf "${REPORT_TAR_NAME}" reports

python3 "${PIPELINE_REPO_DIR}/stages/s3/s3_upload.py" --file "${REPORT_TAR_NAME}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${TAR_PATH_SHORT}"
python3 "${PIPELINE_REPO_DIR}/stages/s3/vat_artifact_post.py"
