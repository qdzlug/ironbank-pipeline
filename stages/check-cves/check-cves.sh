#!/bin/bash
set -Eeuo pipefail
wl_image_path=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')

if [[ "${DISTROLESS:-}" ]]; then
  python3 "${PIPELINE_REPO_DIR}/stages/check-cves/pipeline_wl_compare.py" \
    --image "${wl_image_path}" \
    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/${CI_PIPELINE_ID}.json" \
    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
    --proj_branch "${CI_COMMIT_BRANCH}" \
    --wl_branch "${WL_TARGET_BRANCH}"
else
  python3 "${PIPELINE_REPO_DIR}/stages/check-cves/pipeline_wl_compare.py" \
    --image "${wl_image_path}" \
    --oscap "${ARTIFACT_STORAGE}/scan-results/openscap/report.html" \
    --oval "${ARTIFACT_STORAGE}/scan-results/openscap/report-cve.html" \
    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/${CI_PIPELINE_ID}.json" \
    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
    --proj_branch "${CI_COMMIT_BRANCH}" \
    --wl_branch "${WL_TARGET_BRANCH}"
fi
