#!/bin/bash
set -Eeuo pipefail
shopt -s nullglob # Allow import-artifacts/*/* to match nothing

if [[ "${CLAMAV_WHITELIST:-}" ]]; then
  cp "${PIPELINE_REPO_DIR}/stages/scan-artifacts/clamav-whitelist" /usr/local/share/clamav/clamav_whitelist.ign2
fi

freshclam --config-file /clamav/conf/freshclam.conf
for filename in "${ARTIFACT_STORAGE}"/import-artifacts/*/*; do
  # TODO: fix or temporarily skip scans of large files
  clamscan -irv --max-filesize=1800M --max-scansize=1800M "${filename}" | tee "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
done
