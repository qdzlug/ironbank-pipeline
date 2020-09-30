#!/bin/bash
set -Eeuo pipefail
mkdir -p "${ARTIFACT_DIR}"
pip install boto3
if [ "${CI_COMMIT_BRANCH}" == "master" ]; then
    export BASE_BUCKET_DIRECTORY="container-scan-reports"
fi
directory_date=$(date --utc '+%FT%T.%3N')
export directory_date
export REMOTE_DOCUMENTATION_DIRECTORY="${directory_date}_${CI_PIPELINE_ID}"
export REMOTE_REPORT_DIRECTORY="${REMOTE_DOCUMENTATION_DIRECTORY}/reports"
IMAGE_PATH=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')
export IMAGE_PATH
S3_HTML_LINK="https://s3-us-gov-west-1.amazonaws.com/${S3_REPORT_BUCKET}/${BASE_BUCKET_DIRECTORY}/${CI_PROJECT_NAME}/${IMG_VERSION}"
GPG_PUB_KEY=$(awk '{printf "%s\\n", $0}' "${IB_CONTAINER_GPG_PUBKEY}")

export FILES="${SCAN_DIRECTORY}/*"
export S3_BUCKET="${S3_REPORT_BUCKET}"
export S3_BUCKET_PATH="/${BASE_BUCKET_DIRECTORY}/${IM_NAME}"
export bucket=${S3_BUCKET}
export bucket_path=${S3_BUCKET_PATH}
date="$(date +'%a, %d %b %Y %H:%M:%S %z')"
export date
export content_type="application/json"
export SIG_STRING="GET\n\n${content_type}\n${date}\n/$bucket$bucket_path/repo_map.json"
signature=$(echo -en "${SIG_STRING}" | openssl sha1 -hmac "${S3_SECRET_KEY}" -binary | base64)
export signature
PROJECT_README=$(find . -name "README*" -type f -maxdepth 1 | rev | cut -d/ -f1 | rev)
export PROJECT_README
PROJECT_LICENSE=$(find . -name "LICENSE*" -type f -maxdepth 1 | rev | cut -d/ -f1 | rev)
export PROJECT_LICENSE

res=$(curl -H "Host: $bucket.s3-us-gov-west-1.amazonaws.com"  -H "Date: $date" -H "Content-Type: $content_type" -H "Authorization: AWS ${S3_ACCESS_KEY}:$signature" -s -o /dev/null -w '%{http_code}\n' "https://$bucket.s3-us-gov-west-1.amazonaws.com$bucket_path/repo_map.json")
if ((res == 404)); then
    echo "no prior repo_map."
    export job_type=2
else
    export job_type=1
    echo "updating from latest."
    curl -H "Host: $bucket.s3-us-gov-west-1.amazonaws.com" \
    -H "Date: $date" \
    -H "Content-Type: $content_type" \
    -H "Authorization: AWS ${S3_ACCESS_KEY}:$signature" \
    "https://$bucket.s3-us-gov-west-1.amazonaws.com${bucket_path}/repo_map.json" -o repo_map.json
fi

python3 "${PIPELINE_REPO_DIR}/stages/publish/create_repo_map.py" \
    --repo_name="${IM_NAME}" \
    --approval_status="${IMAGE_APPROVAL_STATUS}" \
    --public_key="${GPG_PUB_KEY}" \
    --image_sha="${IMAGE_ID}" \
    --image_name="${CI_PROJECT_NAME}" \
    --image_tag="${IMG_VERSION}" \
    --image_path="${REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}" \
    --image_url="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${IMAGE_FILE}.tar" \
    --build_number="${CI_PIPELINE_ID}" \
    --image_manifest="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/manifest.json" \
    --manifest_name="manifest.json" \
    --pgp_signature="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${SIG_FILE}.sig" \
    --signature_name="${SIG_FILE}.sig" \
    --version_documentation="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${DOCUMENTATION_FILENAME}.json" \
    --tar_location="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/${REPORT_TAR_NAME}" \
    --tar_name="${IMAGE_FILE}.tar" \
    --openscap_compliance_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/oscap.csv" \
    --openscap_oval_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/oval.csv" \
    --twistlock_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/tl.csv" \
    --anchore_gates_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/anchore_gates.csv" \
    --anchore_security_results="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/anchore_security.csv" \
    --summary_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/summary.csv" \
    --full_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/csvs/all_scans.xlsx" \
    --openscap_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/openscap/report.html" \
    --oval_report="${S3_HTML_LINK}/${REMOTE_REPORT_DIRECTORY}/openscap/report-cve.html" \
    --project_license "${PROJECT_LICENSE}" \
    --project_readme "${PROJECT_README}" \
    --signature_name="${SIG_FILE}.sig" \
    --output_dir="${ARTIFACT_DIR}" \
    --job_type="${job_type}"
mkdir reports
cp -r "${DOCUMENTATION_DIRECTORY}"/reports/* reports/
cp -r "${SCAN_DIRECTORY}"/* reports/
cp "${BUILD_DIRECTORY}/${CI_PROJECT_NAME}-${IMG_VERSION}.tar" "reports/${CI_PROJECT_NAME}-${IMG_VERSION}.tar"
cp "${PROJECT_LICENSE}" "${PROJECT_README}" reports/
ls reports
tar -zcvf "${REPORT_TAR_NAME}" reports
python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file repo_map.json --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IM_NAME}/repo_map.json"
for file in $(find "${DOCUMENTATION_DIRECTORY}" -name "*" -type f); do
    object_path=$(echo ${file#"$ARTIFACT_STORAGE/documentation/"})
    python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "$file" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_DOCUMENTATION_DIRECTORY}/$object_path" ;
done
for file in $(find "${SCAN_DIRECTORY}" -name "*" -type f); do
    report_name=$(echo "$file" | rev | cut -d/ -f1-2 | rev)
    echo "$file"
    python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "$file" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}/$report_name" ;
done
python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "${PROJECT_README}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_README}"
python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "${PROJECT_LICENSE}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}/${PROJECT_LICENSE}"
python3 "${PIPELINE_REPO_DIR}/stages/publish/s3_upload.py" --file "${REPORT_TAR_NAME}" --bucket "${S3_REPORT_BUCKET}" --dest "${BASE_BUCKET_DIRECTORY}/${IMAGE_PATH}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}/${REPORT_TAR_NAME}"
