#!/usr/bin/env bash

set -Eeuo pipefail

if [[ $(echo "${CI_PROJECT_DIR}" | grep -e 'pipeline-test-project') ]]; then
  echo "This job should not run on a 'pipeline-test-project'"
  exit 0
fi

echo "This should not print"

date -u
