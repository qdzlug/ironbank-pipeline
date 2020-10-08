#!/bin/bash
set -Eeuo pipefail
python3 "${PIPELINE_REPO_DIR}/stages/lint/wl_compare_lint.py" \
  --image "${CI_PROJECT_PATH}" \
  --tag "${IMG_VERSION}" \
  --wlbranch "${WL_TARGET_BRANCH}" > lint.env
cat lint.env
