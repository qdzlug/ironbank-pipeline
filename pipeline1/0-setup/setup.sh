#!/bin/bash
set -Eeuo pipefail

## trufflehog
ls # Remove me
git config --global --add safe.directory "${CI_PROJECT_DIR}"
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/trufflehog.py"
ls # Remove me

## image_inspect.py
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/image_inspect.py"

## lint
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/lint_jobs.py"
