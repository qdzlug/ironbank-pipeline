#!/bin/bash
set -Eeuo pipefail
shopt -s nullglob # Allow import-artifacts/*/* to match nothing

freshclam --config-file /clamav/conf/freshclam.conf
for filename in ${ARTIFACT_STORAGE}/import-artifacts/*/*; do
  # TODO: fix or temporarily skip scans of large files
  clamscan -irv --max-filesize=1800M --max-scansize=1800M "${filename}" | tee "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
done
