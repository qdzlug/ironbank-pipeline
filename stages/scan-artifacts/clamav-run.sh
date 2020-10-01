#!/bin/bash
set -Eu
freshclam
for filename in ${ARTIFACT_STORAGE}/import-artifacts/; do
    clamscan -irv --max-filesize=4000M --max-scansize=4000M "${filename}" >> "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
done
clamscan -irv --max-filesize=4000M --max-scansize=4000M "${ARTIFACT_STORAGE}/import-artifacts/" >> "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
cat "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
INFECTED_CONTAINER_FILES=$(grep -e "^Infected files:" "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt" | cut -d ' ' -f3)

if [ "${INFECTED_CONTAINER_FILES}" -gt 0 ]
then
    echo Malware detected in container! Number of findings: "${INFECTED_CONTAINER_FILES}"
    exit 1
fi
