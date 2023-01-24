#!/bin/bash
# From post-build stage originally. Now ClamAV is ran within Anchore
set -Eeuo pipefail
freshclam
clamscan -irv --max-filesize=4000M --max-scansize=4000M "${ARTIFACT_STORAGE}/build/" >"${CLAMAV_SCANS}/scan-image-clamav-report.txt"
cat "${ARTIFACT_DIR}/scan-image-clamav-report.txt"
INFECTED_CONTAINER_FILES=$(grep -e "^Infected files:" "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt" | cut -d ' ' -f3)
if [ "${INFECTED_CONTAINER_FILES}" -gt 0 ]; then
  echo Malware detected in container! Number of findings: "${INFECTED_CONTAINER_FILES}"
  exit 1
fi
