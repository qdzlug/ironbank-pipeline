#!/bin/bash
set -Eeuo pipefail
mkdir -p "${ARTIFACT_DIR}/external-resources/" "${ARTIFACT_DIR}/images/"
touch artifact.env

# Run the download script on the hardening_manifest.yaml file
if [ -f "${CI_PROJECT_DIR}"/hardening_manifest.yaml ]; then
  python3 "${PIPELINE_REPO_DIR}/stages/import-artifacts/downloader.py" -i "${CI_PROJECT_DIR}/hardening_manifest.yaml" -d "${ARTIFACT_DIR}"
else
  echo "No hardening_manifest.yaml file found"
fi
