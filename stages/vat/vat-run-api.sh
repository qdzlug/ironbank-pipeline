import os
import sys
import datetime

CI_PROJECT_DIR = os.getenv('CI_PROJECT_DIR')
COMMIT_SHA_TO_SCAN = os.getenv('COMMIT_SHA_TO_SCAN')
VAT_BACKEND_URL = os.getenv('VAT_BACKEND_URL')

if 'pipeline-test-project' in CI_PROJECT_DIR:
    print("Skipping vat. Cannot push to VAT when working with pipeline test projects...")
    sys.exit(0)

PIPELINE_REPO_DIR = os.getenv('PIPELINE_REPO_DIR')
CI_PIPELINE_ID = os.getenv('CI_PIPELINE_ID')
BUILD_DATE = os.getenv('BUILD_DATE')
BUILD_DATE_TO_SCAN = os.getenv('BUILD_DATE_TO_SCAN')
IMAGE_NAME = os.getenv('IMAGE_NAME')
IMAGE_VERSION = os.getenv('IMAGE_VERSION')
DIGEST_TO_SCAN = os.getenv('DIGEST_TO_SCAN')
BASE_IMAGE = os.getenv('BASE_IMAGE')
BASE_TAG = os.getenv('BASE_TAG')
OSCAP_COMPLIANCE_URL = os.getenv('OSCAP_COMPLIANCE_URL')
CI_PROJECT_URL = os.getenv('CI_PROJECT_URL')
ARTIFACT_STORAGE = os.getenv('ARTIFACT_STORAGE')

REMOTE_REPORT_DIRECTORY = f"{datetime.datetime.now().strftime('%Y-%m-%dT%H:%M:%S')}_{COMMIT_SHA_TO_SCAN}"
os.environ['REMOTE_REPORT_DIRECTORY'] = REMOTE_REPORT_DIRECTORY
os.environ['VAT_API_URL'] = f"{VAT_BACKEND_URL}/internal/import/scan"

#!/bin/bash
# set -Eeuo pipefail
# if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project'; then
#   echo "Skipping vat. Cannot push to VAT when working with pipeline test projects..."
#   exit 0
# fi
# REMOTE_REPORT_DIRECTORY="$(date +%FT%T)_${COMMIT_SHA_TO_SCAN}"
# export REMOTE_REPORT_DIRECTORY
# export VAT_API_URL="${VAT_BACKEND_URL}/internal/import/scan"

# output OSCAP link variables for the VAT stage to use
python3 "${PIPELINE_REPO_DIR}/stages/vat/vat_import.py" \
  --api_url "${VAT_API_URL}" \
  --job_id "${CI_PIPELINE_ID}" \
  --timestamp "$(date --utc '+%FT%TZ')" \
  --scan_date "${BUILD_DATE}" \
  --build_date "${BUILD_DATE_TO_SCAN}" \
  --commit_hash "${COMMIT_SHA_TO_SCAN}" \
  --container "${IMAGE_NAME}" \
  --version "${IMAGE_VERSION}" \
  --digest "${DIGEST_TO_SCAN}" \
  --parent "${BASE_IMAGE:-}" \
  --parent_version "${BASE_TAG:-}" \
  --comp_link "${OSCAP_COMPLIANCE_URL:-''}" \
  --repo_link "${CI_PROJECT_URL}" \
  --oscap "${ARTIFACT_STORAGE}/scan-results/openscap/compliance_output_report.xml" \
  --twistlock "${ARTIFACT_STORAGE}/scan-results/twistlock/twistlock_cve.json" \
  --anchore-sec "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_security.json" \
  --anchore-gates "${ARTIFACT_STORAGE}/scan-results/anchore/anchore_gates.json"

