#!/bin/bash
set -Eeuo pipefail
if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project'; then
  echo "Skipping vat. Cannot push to VAT when working with pipeline test projects..."
  exit 0
fi
export BASE_BUCKET_DIRECTORY="container-scan-reports"
REMOTE_REPORT_DIRECTORY="$(date +%FT%T)_${CI_COMMIT_SHA}"
export REMOTE_REPORT_DIRECTORY
export S3_HTML_LINK="${S3_REPORT_BUCKET}/${BASE_BUCKET_DIRECTORY}/${CI_PROJECT_NAME}/${IMAGE_VERSION}/${REMOTE_REPORT_DIRECTORY}"
IM_NAME=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')
export IM_NAME

# OpenSCAP report links are available from the CSV Output job. Once VAT team updates vat_import.py
# script to use these values we can begin passing updated arguments

pip3 install --upgrade pip setuptools wheel minepy python-gitlab
pip3 install -r "${PIPELINE_REPO_DIR}/stages/vat/requirements.txt"

#
# TODO: BASE_IMAGE and BASE_TAG should be pulled out of the `hardening_manifest.yaml`
#
python3 "${PIPELINE_REPO_DIR}/stages/vat/vat_import.py" \
  --db "${vat_db_database_name}" \
  --user "${vat_db_connection_user}" \
  --host "${vat_db_host}" \
  --csv_dir "${ARTIFACT_DIR}" \
  --jenkins "${CI_PIPELINE_ID}" \
  --container "${IM_NAME}" \
  --version "${IMAGE_VERSION}" \
  --parent "${BASE_IMAGE:-}" \
  --password "${vat_db_connection_pass}" \
  --parent_version "${BASE_TAG:-}" \
  --scan_date "$(date +%FT%T)" \
  --sec_link "${OSCAP_CVE_URL}/" \
  --comp_link "${OSCAP_COMPLIANCE_URL}/"
