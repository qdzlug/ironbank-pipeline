#!/usr/bin/env bash

set -Eeuo pipefail

python3 "${PIPELINE_REPO_DIR}/stages/lint/wl_compare_lint.py" > lint.env

cat lint.env
