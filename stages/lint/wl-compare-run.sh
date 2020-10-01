#!/bin/bash
set -Eexuo pipefail
python3 "${PIPELINE_REPO_DIR}/stages/lint/wl_compare_lint.py" \
  --image "${CI_PROJECT_PATH}" \
  --tag "${IMG_VERSION}" \
  --glkey "${PYTHON_GITLAB_KEY}" \
  --wlbranch "${WL_TARGET_BRANCH}" > lint.env
cat lint.env
