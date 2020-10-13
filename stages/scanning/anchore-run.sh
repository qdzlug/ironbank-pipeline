#!/bin/bash
set -Eeuo pipefail
mkdir -p "${ANCHORE_SCANS}"
# Install anchore-cli
# TODO: Install the anchore-cli on the runner
pip3 install --user --upgrade anchorecli
# The anchore-cli is not installed along the normal path so set
# the path appropriately.
# TODO: Configure the anchore-cli path on the runner
ANCHORE_CLI_PATH="$(python3 -m site --user-base)/bin"
export ANCHORE_CLI_PATH
# Set up the environment for the anchore-cli commands and anchore_scan.py script
export ANCHORE_CLI_URL="${anchore_server_address}"
export ANCHORE_CLI_USER="${anchore_username}"
export ANCHORE_CLI_PASS="${anchore_password}"
export ANCHORE_DEBUG="${anchore_debug}"
export ANCHORE_SCAN_DIRECTORY="${ANCHORE_SCANS}"
export IMAGE_NAME="${REGISTRY1_URL}/ironbank-staging/${IM_NAME}:${IMG_VERSION}-${CI_PIPELINE_ID}"
export IMAGE_ID="${IMAGE_ID}"
"${ANCHORE_CLI_PATH}/anchore-cli" image add --dockerfile ./Dockerfile "${IMAGE_NAME}"
"${ANCHORE_CLI_PATH}/anchore-cli" image wait --timeout "${anchore_timeout}" "${IMAGE_NAME}"
python3 "${PIPELINE_REPO_DIR}/stages/scanning/anchore_scan.py"
