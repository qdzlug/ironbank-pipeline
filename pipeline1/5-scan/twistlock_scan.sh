#!/bin/bash

set -euo pipefail

for SCAN_LOGIC_DIR in "$ARTIFACT_STORAGE/scan-logic"/*; do

  # amd64, arm64, ..
  PLATFORM=$(basename "$SCAN_LOGIC_DIR")

  URI_BASENAME=$(awk -F'=' '/IMAGE_TO_SCAN/ { print $2 }' "$SCAN_LOGIC_DIR/scan_logic.env" | awk -F':' '{ print $1 }')
  URI_DIGEST=$(awk -F'=' '/DIGEST_TO_SCAN/ { print $2 }' "$SCAN_LOGIC_DIR/scan_logic.env")

  echo "scanning $PLATFORM (${URI_BASENAME}@${URI_DIGEST})"
  # artifacts
  mkdir -p "${ARTIFACT_DIR}/${PLATFORM}"

  podman pull --authfile "${DOCKER_AUTH_FILE_PULL}" "${URI_BASENAME}@${URI_DIGEST}"
  twistcli images scan --address "${TWISTLOCK_URL}" --podman-path podman --custom-labels --output-file "${ARTIFACT_DIR}/${PLATFORM}/twistlock_cve.json" --details "${URI_BASENAME}@${URI_DIGEST}" | tee "${ARTIFACT_DIR}/${PLATFORM}/twistcli-details.txt"
  ls "${ARTIFACT_DIR}/${PLATFORM}/twistlock_cve.json"
  chmod 0644 "${ARTIFACT_DIR}/${PLATFORM}/twistlock_cve.json"
done
