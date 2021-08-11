#!/bin/bash
set -Eeuo pipefail

echo "Creating and signing Manifest JSON"
"${PIPELINE_REPO_DIR}/stages/documentation/sign-manifest-run.sh"

echo "Creating documentation and scan-metadata JSON files"
"${PIPELINE_REPO_DIR}/stages/documentation/write-json-docs-run.sh"
