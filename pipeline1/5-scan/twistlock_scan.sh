#!/bin/bash

set -euo pipefail

for SCAN_LOGIC_DIR in "$ARTIFACT_STORAGE/scan-logic"/*;
do

  # amd64, arm64, ..
  PLATFORM=$(basename "$SCAN_LOGIC_DIR")

  IMAGE_TO_SCAN=$(grep 'IMAGE_TO_SCAN' "$SCAN_LOGIC_DIR/scan_logic.env")
  DIGEST_TO_SCAN=$(grep 'DIGEST_TO_SCAN' "$SCAN_LOGIC_DIR/scan_logic.env")

  # scan by sha uri
  URI_BASENAME=$(echo "$IMAGE_TO_SCAN" | awk -F':' '{ print $1 }')
  URI_TO_SCAN="$URI_BASENAME@$DIGEST_TO_SCAN"

  echo "scanning $PLATFORM ($URI_TO_SCAN)"
  # artifacts
  mkdir -p "${ARTIFACT_DIR}/${PLATFORM}"

  podman pull --authfile "${DOCKER_AUTH_FILE_PULL}" "${URI_TO_SCAN}"
  twistcli --version > "${ARTIFACT_DIR}/${PLATFORM}/twistlock-version.txt"
  twistcli images scan --address "${TWISTLOCK_URL}" --podman-path podman --custom-labels --output-file "${ARTIFACT_DIR}/${PLATFORM}/twistlock_cve.json" --details "${URI_TO_SCAN}" | tee "${ARTIFACT_DIR}/${PLATFORM}/twistcli-details.txt"
  ls "${ARTIFACT_DIR}/${PLATFORM}/twistlock_cve.json"
  chmod 0644 "${ARTIFACT_DIR}/${PLATFORM}/twistlock_cve.json"
done
