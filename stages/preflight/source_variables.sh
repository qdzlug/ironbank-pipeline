#!/bin/bash
set -Eeuo pipefail

# Determine if the ironbank.yaml file exists
# Parse the files if it does
# Generate an ironbank.yaml file if it does not
if [ -f "${CI_PROJECT_DIR}"/ironbank.yaml ]; then
  python3 "${PIPELINE_REPO_DIR}/stages/preflight/source_variables.py" -i "${CI_PROJECT_DIR}/ironbank.yaml" >>source.env
else
  # TODO: add code for generating ironbank.yaml
  echo "No ironbank.yaml file found. Creating one..."
fi