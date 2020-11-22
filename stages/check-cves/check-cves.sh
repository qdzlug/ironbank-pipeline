#!/bin/env bash
set -Eeuo pipefail

if [[ "${DISTROLESS:-}" ]]; then
  python3 "${PIPELINE_REPO_DIR}/stages/check-cves/pipeline_wl_compare.py" \
    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
    --proj_branch "${CI_COMMIT_BRANCH}"
else
  python3 "${PIPELINE_REPO_DIR}/stages/check-cves/pipeline_wl_compare.py" \
    --oscap "${ARTIFACT_STORAGE}/scan-results/openscap/report.html" \
    --oval "${ARTIFACT_STORAGE}/scan-results/openscap/report-cve.html" \
    --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
    --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
    --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json" \
    --proj_branch "${CI_COMMIT_BRANCH}"
fi
