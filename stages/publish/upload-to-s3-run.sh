#!/bin/bash
set -Eeuo pipefail

#check image approval status, fail if not approved
if [ "${CI_COMMIT_BRANCH}" == "master" ] && [ "${IMAGE_APPROVAL_STATUS}" != "approved" ]; then
  echo "Skipping publish. Cannot publish images that are not approved."
  exit 1
fi

if [[ $(echo "${CI_PROJECT_DIR}" | grep -e 'pipeline-test-project') ]] && [ "${CI_COMMIT_BRANCH}" == "master" ]; then
  echo "Skipping publish. Cannot publish when working with pipeline test projects master branch..."
  exit 0
fi
mkdir -p "${ARTIFACT_DIR}"

# pip install boto3 ushlex
if [ "${CI_COMMIT_BRANCH}" == "master" ]; then
  BASE_BUCKET_DIRECTORY="container-scan-reports"
fi

IMAGE_PATH=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')

PROJECT_README=$(find . -name "README*" -type f -maxdepth 1 | rev | cut -d/ -f1 | rev)
PROJECT_LICENSE=$(find . -name "LICENSE*" -type f -maxdepth 1 | rev | cut -d/ -f1 | rev)

source "${PIPELINE_REPO_DIR}"/stages/publish/repo_map_vars.sh

python3 "${PIPELINE_REPO_DIR}"/stages/publish/create_repo_map.py --target ${BASE_BUCKET_DIRECTORY}/"${IMAGE_PATH}"/repo_map.json

mkdir reports

cp -r "${DOCUMENTATION_DIRECTORY}"/reports/* reports/
cp -r "${SCAN_DIRECTORY}"/* reports/
cp "${BUILD_DIRECTORY}"/"${CI_PROJECT_NAME}"-"${IMG_VERSION}".tar reports/"${CI_PROJECT_NAME}"-"${IMG_VERSION}".tar
cp "${PROJECT_LICENSE}" "${PROJECT_README}" reports/

# Debug
ls reports

tar -zcvf "${REPORT_TAR_NAME}" reports

python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file repo_map.json --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IM_NAME}/repo_map.json"
for file in $(find "${DOCUMENTATION_DIRECTORY}" -name "*" -type f); do
  object_path="${file#"$ARTIFACT_STORAGE/documentation/"}"
  python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "$file" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_DOCUMENTATION_DIRECTORY}/$object_path"
done

for file in $(find "${SCAN_DIRECTORY}" -name "*" -type f); do
  report_name=$(echo "$file" | rev | cut -d/ -f1-2 | rev)
  echo "$file"
  python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "$file" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}/$report_name"
done

python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "${PROJECT_README}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_README}"
python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "${PROJECT_LICENSE}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_LICENSE}"
python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "${REPORT_TAR_NAME}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}/${REPORT_TAR_NAME}"
