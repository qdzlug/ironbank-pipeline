#!/bin/bash
set -Eeuo pipefail
mkdir -p "${ARTIFACT_DIR}/external-resources/" "${ARTIFACT_DIR}/images/"

# Run the download script on the hardening_manifest.yaml file
echo "${DOCKER_AUTH_CONFIG_PULL}" | base64 -d >>/tmp/prod_auth.json
python3 "${PIPELINE_REPO_DIR}/stages/import-artifacts/downloader.py"
