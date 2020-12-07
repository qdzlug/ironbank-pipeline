#!/bin/bash
set -Eeuo pipefail
mkdir -p "${ARTIFACT_DIR}/external-resources/" "${ARTIFACT_DIR}/images/"

# Run the download script on the hardening_manifest.yaml file
echo "${DOCKER_AUTH_CONFIG_PULL}" | base64 -d >>/tmp/prod_auth.json
if [ -f "${CI_PROJECT_DIR}/hardening_manifest.yaml" ]; then
  python3 "${PIPELINE_REPO_DIR}/stages/import-artifacts/downloader.py" -i "${CI_PROJECT_DIR}/hardening_manifest.yaml" -d "${ARTIFACT_DIR}"
elif [ -f "${ARTIFACT_STORAGE}/preflight/hardening_manifest.yaml" ]; then
  echo "Using autogenerated hardening_manifest.yaml"
  python3 "${PIPELINE_REPO_DIR}/stages/import-artifacts/downloader.py" -i "${ARTIFACT_STORAGE}/preflight/hardening_manifest.yaml" -d "${ARTIFACT_DIR}"
else
  echo "INTERNAL ERROR: No hardening_mainfest.yaml file found"
  exit 1
fi
