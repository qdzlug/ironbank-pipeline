#!/bin/bash
set -Eeuo pipefail

echo "Signing Image"
# shellcheck source=./stages/documentation/sign-image-run.sh
source "${PIPELINE_REPO_DIR}/stages/documentation/sign-image-run.sh"

echo "Creating and signing Manifest JSON"
"${PIPELINE_REPO_DIR}/stages/documentation/sign-manifest-run.sh"

echo "Creating documentation and scan-metadata JSON files"
"${PIPELINE_REPO_DIR}/stages/documentation/write-json-docs-run.sh"
