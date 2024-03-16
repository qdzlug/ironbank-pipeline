#!/bin/bash
set -Eeuo pipefail

for SCAN_LOGIC_DIR in "$ARTIFACT_STORAGE/scan-logic"/*; do

  # amd64, arm64, ..
  PLATFORM=$(basename "$SCAN_LOGIC_DIR")
  source "$SCAN_LOGIC_DIR"/"$PLATFORM"/scan_logic.env

  # Create manifest.json

  mkdir -p "${ARTIFACT_DIR}/reports/${PLATFORM}"
  jq -n '
  {
    "critical": {
      "type": "atomic container signature",
      "image": {
        "podman-manifest-digest": env.DIGEST_TO_SCAN
      },
      "identity": {
        "podman-reference": env.IMAGE_TO_SCAN
      }
    },
    "optional": {
      "creator": env.GPG_VERSION
    }
  }' >"${ARTIFACT_DIR}/reports/${PLATFORM}/manifest.json"
  cat "${ARTIFACT_DIR}/reports/${PLATFORM}/manifest.json"

done
