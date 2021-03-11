#!/bin/bash
set -Eeuo pipefail

curl -i -X POST -H 'Content-Type: application/json' -d "{\"text\": \"Check CVE Failure for ${CI_PROJECT_NAME}: ${CI_PROJECT_URL}/-/pipelines/${CI_PIPELINE_ID}\"}" "${CHECK_CVES_FAILURE_WEBHOOK}"
