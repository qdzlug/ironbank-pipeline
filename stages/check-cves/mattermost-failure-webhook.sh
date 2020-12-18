#!/bin/bash
set -Eeuo pipefail

curl -i -X POST -H 'Content-Type: application/json' -d '{"text": "FAILURE"}' "${CHECK_CVES_FAILURE_WEBHOOK}"