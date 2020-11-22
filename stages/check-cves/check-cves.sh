#!/bin/env bash
set -Eeuo pipefail

if [[ "${DISTROLESS:-}" ]]; then
  python3 "${PIPELINE_REPO_DIR}/stages/check-cves/pipeline_wl_compare.py"
else
  python3 "${PIPELINE_REPO_DIR}/stages/check-cves/pipeline_wl_compare.py" \
    --oscap "${ARTIFACT_STORAGE}/scan-results/openscap/report.html" \
    --oval "${ARTIFACT_STORAGE}/scan-results/openscap/report-cve.html"
fi
