#!/bin/bash
set -Eeuo pipefail
mkdir -p "${ARTIFACT_DIR}/external-resources/" "${ARTIFACT_DIR}/images/"
touch artifact.env

pip3 install requests boto3

if [ -f "${CI_PROJECT_DIR}"/download.json ]; then
    echo "download.json file found. Converting json to yaml."
    mkdir -p "${ARTIFACT_DIR}"/converted-file/
    touch "${ARTIFACT_DIR}"/converted-file/download.yaml
    python3 "${PIPELINE_REPO_DIR}/stages/import-artifacts/json_yaml_converter.py" -i "${CI_PROJECT_DIR}/download.json" -o "${ARTIFACT_DIR}"/converted-file/download.yaml
    python3 "${PIPELINE_REPO_DIR}/stages/import-artifacts/downloader.py" -i "${ARTIFACT_DIR}"/converted-file/download.yaml -d "${ARTIFACT_DIR}"
elif [ -f "${CI_PROJECT_DIR}"/download.yaml ]; then
    python3 "${PIPELINE_REPO_DIR}/stages/import-artifacts/downloader.py" -i "${CI_PROJECT_DIR}/download.yaml" -d "${ARTIFACT_DIR}"
else
    echo "No Download file found"
fi
