#!/bin/bash
set -Eeuo pipefail

## image_inspect.py
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/image_inspect.py"

## lint
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/lint_jobs.py"
echo $?

## trufflehog
git config --global --add safe.directory "${CI_PROJECT_DIR}"
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/trufflehog.py"
