#!/bin/bash
set -Eeuo pipefail
if [ -z "${IMG_VERSION:-}" ]; then
  echo
  echo "ERROR: Missing IMG_VERSION variable. Do you have the appropriate files in your repository?"
  echo
  echo "ERROR: This is an easy thing to solve, please reference the previous stage (load scripts) as well as the MR below to resolve your issue."
  echo "ERROR: https://repo1.dsop.io/ironbank-tools/ironbank-pipeline/-/merge_requests/30"
  echo
  exit 1
fi
