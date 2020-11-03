#!/bin/bash
set -Eeuo pipefail
mkdir -p "${ARTIFACT_DIR}/external-resources/" "${ARTIFACT_DIR}/images/"
touch artifact.env

# pip3 install --user requests boto3

# Run the download script on the ironbank.yaml file
if [ -f "${CI_PROJECT_DIR}"/ironbank.yaml ]; then
  python3 "${PIPELINE_REPO_DIR}/stages/import-artifacts/downloader.py" -i "${CI_PROJECT_DIR}/ironbank.yaml" -d "${ARTIFACT_DIR}"
else
  echo "No ironbank.yaml file found"
fi
