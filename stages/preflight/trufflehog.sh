#!/bin/bash
set -Eeuo pipefail

report_name="trufflehog.txt"
git fetch origin -q
if [ "${CI_COMMIT_BRANCH}" == "master" ]; then
  echo "Check is run on development and feature branches"
  exit 0
elif [ "${CI_COMMIT_BRANCH}" == "development" ]; then
  since_commit=$(git log origin/master.. --stat | grep "commit" | tail -1 | awk '{print $2}')
else
  since_commit=$(git log origin/development.. --stat | grep "commit" | tail -1 | awk '{print $2}')
fi
# if since_commit doesn't exist run trufflehog3 with --no-history flag
if [ -z "${since_commit}" ]; then
  history_cmd="--since_commit ${since_commit}"
else
  history_cmd="--no-history"
fi

set -x
trufflehog_cmd="trufflehog3 --no-entropy ${history_cmd} --branch ${CI_COMMIT_BRANCH} ."
set +x
# Could add exceptions using --exclude_paths <exclusion file>
set +e
"${trufflhog_cmd}"
set -e
failure_count=$(grep -i '"Reason":' "${report_name}" | wc -l | tr -d ' ')
if [ $failure_count -eq 0 ]; then
  exit 0
else
fi
echo "ERROR Trufflehog scan failed. Failure count: ${failure_count}"
echo "ERROR The offening commits need to be removed from your commit history"
echo "ERROR To review "
exit 1
