#!/bin/bash
set -Eeuo pipefail

# Determine if the description.yaml file exists
# Parse the files if it does
# Generate an description.yaml file if it does not
if [ -f "${CI_PROJECT_DIR}"/description.yaml ]; then
  python3 "${PIPELINE_REPO_DIR}/stages/preflight/source_variables.py" -i "${CI_PROJECT_DIR}/description.yaml" >>source.env
else
  # TODO: add code for generating description.yaml
  echo "No description.yaml file found. Creating one..."
fi
