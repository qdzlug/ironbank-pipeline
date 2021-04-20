#!/bin/bash
set -Eeuo pipefail

echo "Signing Image"
"${PIPELINE_REPO_DIR}/stages/documentation/sign-image-run.sh"

export IMAGE_TAR_SHA

echo "Creating and signing Manifest JSON"
"${PIPELINE_REPO_DIR}/stages/documentation/sign-manifest-run.sh"

echo "Creating documentation and scan-metadata JSON files"
"${PIPELINE_REPO_DIR}/stages/documentation/write-json-docs-run.sh"
