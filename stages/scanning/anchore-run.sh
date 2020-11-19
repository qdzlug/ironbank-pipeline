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

# Add the image to Anchore along with it's Dockerfile. Use the `--force` flag to force
# a reanalysis of the image on pipeline reruns where the digest has not changed.
anchore-cli image add --noautosubscribe --dockerfile ./Dockerfile --force "${IMAGE_NAME}"
anchore-cli image wait --timeout "${anchore_timeout}" "${IMAGE_NAME}"

python3 "${PIPELINE_REPO_DIR}/stages/scanning/anchore_scan.py"
