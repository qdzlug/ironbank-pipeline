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

python3 "${PIPELINE_REPO_DIR}/stages/vat/vat_import.py" \
  --db "${vat_db_database_name}" \
  --user "${vat_db_connection_user}" \
  --host "${vat_db_host}" \
  --csv_dir "${ARTIFACT_DIR}" \
  --job_id "${CI_PIPELINE_ID}" \
  --container "${IMAGE_NAME}" \
  --version "${IMAGE_VERSION}" \
  --parent "${BASE_IMAGE:-}" \
  --password "${vat_db_connection_pass}" \
  --parent_version "${BASE_TAG:-}" \
  --scan_date "$(date +%FT%T)" \
  --sec_link "${OSCAP_CVE_URL}" \
  --comp_link "${OSCAP_COMPLIANCE_URL}" \
  --repo_link "${CI_PROJECT_URL}"
