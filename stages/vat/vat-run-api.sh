#!/bin/bash
set -Eeuo pipefail
if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project'; then
  echo "Skipping vat. Cannot push to VAT when working with pipeline test projects..."
  exit 0
fi
export BASE_BUCKET_DIRECTORY="container-scan-reports"
REMOTE_REPORT_DIRECTORY="$(date +%FT%T)_${CI_COMMIT_SHA}"
export REMOTE_REPORT_DIRECTORY
export VAT_API_URL="${VAT_BACKEND_SERVER_ADDRESS}/internal/import/scan"

python3 "${PIPELINE_REPO_DIR}/stages/vat/new_vat_import.py" \
  --api_url "${VAT_API_URL}" \
  --csv_dir "${ARTIFACT_DIR}" \
  --job_id "${CI_PIPELINE_ID}" \
  --scan_date "$(date +%FT%T)" \
  --commit_hash "${CI_COMMIT_SHA}" \
  --container "${IMAGE_NAME}" \
  --version "${IMAGE_VERSION}" \
  --digest "${IMAGE_PODMAN_SHA}" \
  --parent "${BASE_IMAGE:-}" \
  --parent_version "${BASE_TAG:-}" \
  --comp_link "${OSCAP_COMPLIANCE_URL}" \
  --repo_link "${CI_PROJECT_URL}"

# ----------------------------------------------------
# pip3 install bs4 pandas argparse openpyxl gitpython
if [[ "${DISTROLESS:-}" ]]; then
  python3 "${PIPELINE_REPO_DIR}/stages/csv-output/pipeline_job_gen.py" \
    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
    --output-dir "${CSV_REPORT}"/
else
  # output OSCAP link variables for the VAT stage to use
  report_artifact_path='/artifacts/browse/ci-artifacts/scan-results/openscap/'
  python3 "${PIPELINE_REPO_DIR}/stages/csv-output/pipeline_job_gen.py" \
    --oscap "${ARTIFACT_STORAGE}/scan-results/openscap/compliance_output_report.xml" \
    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
    --output-dir "${CSV_REPORT}"/
fi

