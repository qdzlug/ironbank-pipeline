#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $(echo "${CI_PROJECT_DIR}" | grep -e 'pipeline-test-project') ]] && [ "${CI_COMMIT_BRANCH}" == "master" ]; then
    echo "Skipping publish. Cannot publish when working with pipeline test projects master branch..."
    exit 0
fi

echo "This should not run on a master branch"

date -u
