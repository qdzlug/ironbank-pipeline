#!/bin/bash
set -Eeuo pipefail
# if [[ $(echo "${CI_PROJECT_DIR}" | grep -e 'pipeline-test-project') ]]; then
#   echo "Skipping vat. Cannot push to VAT when working with pipeline test projects..."
#   exit 0
# fi
export BASE_BUCKET_DIRECTORY="container-scan-reports"
REMOTE_REPORT_DIRECTORY="$(date +%FT%T)_${CI_COMMIT_SHA}"
export REMOTE_REPORT_DIRECTORY
export S3_HTML_LINK="${S3_REPORT_BUCKET}/${BASE_BUCKET_DIRECTORY}/${CI_PROJECT_NAME}/${IMG_VERSION}/${REMOTE_REPORT_DIRECTORY}"
IM_NAME=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')
export IM_NAME
# python3 "${PIPELINE_REPO_DIR}/stages/vat/get_parent_info.py" --image "${CI_PROJECT_PATH}" --tag "${IMG_VERSION}" \
#   --glkey "${PYTHON_GL_KEY}" --wlbranch "${WL_TARGET_BRANCH}" --output 'environment.sh'
# source environment.sh
# cat environment.sh

  pip3 install --upgrade pip setuptools wheel minepy python-gitlab
  pip3 install -r "${PIPELINE_REPO_DIR}/stages/vat/requirements.txt"

  python3 "${PIPELINE_REPO_DIR}/stages/vat/vat_import.py" \
    --db "vat-db" \
    --user "${vat_test_db_username}" \
    --host "mariadb.ironbank-vat-test.svc.cluster.local" \
    --csv_dir "${ARTIFACT_DIR}" \
    --jenkins "${CI_PIPELINE_ID}" \
    --container "${IM_NAME}" \
    --version "${IMG_VERSION}" \
    --parent "${BASE_IMAGE:-}" \
    --password "${vat_test_db_password}" \
    --parent_version "${BASE_TAG:-}" \
    --scan_date "$(date +%FT%T)" \
    --link "${OPENSCAP}/" \
    --debug
