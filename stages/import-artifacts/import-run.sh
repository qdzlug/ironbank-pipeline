#!/bin/bash
set -Eeuo pipefail
mkdir -p "${ARTIFACT_DIR}/external-resources/" "${ARTIFACT_DIR}/images/"
touch artifact.env

# Run the download script on the download.yaml file
if [ -f "${CI_PROJECT_DIR}"/download.yaml ]; then
  python3 "${PIPELINE_REPO_DIR}/stages/import-artifacts/downloader.py" -i "${CI_PROJECT_DIR}/download.yaml" -d "${ARTIFACT_DIR}"
else
  echo "No download.yaml file found"
fi
