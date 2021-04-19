#!/bin/bash
set -Eeuo pipefail

echo "Signing Image"
./sign-image-run.sh

echo "Signing Manifest JSON"
./sign-manifest-run.sh

echo "Creating documentation and scan-metadata JSON files"
./write-json-docs-run.sh
