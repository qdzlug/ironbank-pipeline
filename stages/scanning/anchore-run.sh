#!/usr/bin/env bash
set -Eeuo pipefail

mkdir -p "${ANCHORE_SCANS}"

# Set up the environment for the anchore-cli commands and anchore_scan.py script
export ANCHORE_CLI_URL="${anchore_server_address}"
export ANCHORE_CLI_USER="${anchore_username}"
export ANCHORE_CLI_PASS="${anchore_password}"
export ANCHORE_SCAN_DIRECTORY="${ANCHORE_SCANS}"
export IMAGE_NAME="${REGISTRY1_URL}/ironbank-staging/${IM_NAME}:${IMG_VERSION}-${CI_PIPELINE_ID}"
export IMAGE_ID="${IMAGE_ID}"

python3 "${PIPELINE_REPO_DIR}/stages/scanning/anchore_scan.py"
