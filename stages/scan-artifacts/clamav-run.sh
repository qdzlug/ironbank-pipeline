#!/bin/bash
set -Eeuo pipefail
shopt -s nullglob # Allow import-artifacts/*/* to match nothing

freshclam
for filename in ${ARTIFACT_STORAGE}/import-artifacts/*/*; do
    # TODO: fix or temporarily skip scans of large files
    clamscan -irv --max-filesize=4000M --max-scansize=4000M "${filename}" | tee "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
done
