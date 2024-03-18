#!/bin/bash
set -Eeuo pipefail

# wrap the setup jobs in a shell script to support pipefail

## image_inspect.py
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/image_inspect.py"

## lint
set +e
( python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/lint_jobs.py"; ) || (($?==100 ? 1 : 0)) && echo "lint OK"
set -e

## trufflehog
git config --global --add safe.directory "${CI_PROJECT_DIR}"
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/trufflehog.py"
