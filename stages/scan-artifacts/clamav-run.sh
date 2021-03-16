#!/bin/bash
set -Eeuo pipefail
shopt -s nullglob # Allow import-artifacts/*/* to match nothing

if [[ "${CLAMAV_WHITELIST:-}" ]]; then
  cp "clamav-whitelist" /usr/local/share/clamav/clamav_whitelist.ign2
fi

# Commenting out the following because we are getting rate limited
# freshclam --config-file /clamav/conf/freshclam.conf
for filename in "${ARTIFACT_STORAGE}"/import-artifacts/*/*; do
  # TODO: fix or temporarily skip scans of large files
  clamscan -irv --max-filesize=4000M --max-scansize=4000M "${filename}" | tee "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
done
