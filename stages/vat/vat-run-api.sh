#!/bin/bash
set -Eeuo pipefail
if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project'; then
  echo "Skipping vat. Cannot push to VAT when working with pipeline test projects..."
  exit 0
fi
REMOTE_REPORT_DIRECTORY="$(date +%FT%T)_${COMMIT_SHA_TO_SCAN}"
export REMOTE_REPORT_DIRECTORY
export VAT_API_URL="${VAT_BACKEND_URL}/internal/import/scan"

# output OSCAP link variables for the VAT stage to use
python3 "${PIPELINE_REPO_DIR}/stages/vat/vat_import.py" \
  --api_url "${VAT_API_URL}" \
  --job_id "${CI_PIPELINE_ID}" \
  --timestamp "$(date --utc '+%FT%TZ')" \
  --scan_date "${BUILD_DATE}" \
  --build_date "${BUILD_DATE_TO_SCAN}" \
  --commit_hash "${COMMIT_SHA_TO_SCAN}" \
  --container "${IMAGE_NAME}" \
  --version "${IMAGE_VERSION}" \
  --digest "${DIGEST_TO_SCAN}" \
  --parent "${BASE_IMAGE:-}" \
  --parent_version "${BASE_TAG:-}" \
  --comp_link "${OSCAP_COMPLIANCE_URL:-''}" \
  --repo_link "${CI_PROJECT_URL}" \
  --oscap "${ARTIFACT_STORAGE}/scan-results/openscap/compliance_output_report.xml" \
  --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
  --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
  --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json"

