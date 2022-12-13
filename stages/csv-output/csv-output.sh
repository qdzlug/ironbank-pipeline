##!/bin/bash
#set -Eeuo pipefail
#
#mkdir -p "${CSV_REPORT}"
#
#env_filename="csv_output.env"
#
#touch "${env_filename}"
#if [[ "${DISTROLESS:-}" ]]; then
#  echo "OSCAP_COMPLIANCE_URL=''" >>"${env_filename}"
#  python3 "${PIPELINE_REPO_DIR}/stages/csv-output/pipeline_csv_gen.py" \
#    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
#    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
#    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
#    --sbom-dir "${ARTIFACT_STORAGE}/scan-results/anchore/sbom" \
#    --output-dir "${CSV_REPORT}"/
#else
#  # output OSCAP link variables for the VAT stage to use
#  report_artifact_path='/artifacts/browse/ci-artifacts/scan-results/openscap/'
#  echo "OSCAP_COMPLIANCE_URL=${OSCAP_COMPLIANCE_URL}${report_artifact_path}" >>"${env_filename}"
#  cat "${env_filename}"
#  python3 "${PIPELINE_REPO_DIR}/stages/csv-output/pipeline_csv_gen.py" \
#    --oscap "${ARTIFACT_STORAGE}/scan-results/openscap/compliance_output_report.xml" \
#    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
#    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
#    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
#    --sbom-dir "${ARTIFACT_STORAGE}/scan-results/anchore/sbom" \
#    --output-dir "${CSV_REPORT}"/
#fi
#python3 "${PIPELINE_REPO_DIR}"/stages/csv-output/excel_convert.py -i "${CSV_REPORT}"/ -o "${CSV_REPORT}"/"${CI_PROJECT_NAME}":"${IMAGE_VERSION}"-"${CI_PIPELINE_ID}"-justifications.xlsx
#
#echo "OSCAP_CVE_URL=''" >>"${env_filename}"
#