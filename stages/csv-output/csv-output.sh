#!/bin/bash
set -Eeuo pipefail

mkdir -p "${CSV_REPORT}"

env_filename="csv_output.env"

touch "${env_filename}"
# pip3 install --upgrade pip
# pip3 install bs4 pandas argparse openpyxl gitpython
if [[ "${DISTROLESS:-}" ]]; then
  python3 "${PIPELINE_REPO_DIR}/stages/csv-output/pipeline_csv_gen.py" \
    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
    --output-dir "${CSV_REPORT}"/
else
  # output OSCAP link variables for the VAT stage to use
  report_artifact_path='/artifacts/browse/ci-artifacts/scan-results/openscap/'
  #echo "OSCAP_CVE_URL=${OSCAP_CVE_URL}${report_artifact_path}" >>"${env_filename}"
  #echo "OSCAP_COMPLIANCE_URL=${OSCAP_COMPLIANCE_URL}${report_artifact_path}" >>"${env_filename}"
  cat "${env_filename}"
  python3 "${PIPELINE_REPO_DIR}/stages/csv-output/pipeline_csv_gen.py" \
    --oscap "${ARTIFACT_STORAGE}/scan-results/openscap/report.html" \
    --oval "${ARTIFACT_STORAGE}/scan-results/openscap/report-cve.html" \
    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
    --output-dir "${CSV_REPORT}"/
fi
python3 "${PIPELINE_REPO_DIR}"/stages/csv-output/justifier.py -i "${CSV_REPORT}"/all_scans.xlsx -o "${CSV_REPORT}"/"${CI_PROJECT_NAME}":"${IMAGE_VERSION}"-"${CI_PIPELINE_ID}"-justifications.xlsx -s "${IM_NAME}"
