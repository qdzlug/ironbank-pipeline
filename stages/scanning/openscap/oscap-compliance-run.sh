#!/bin/bash
set -Eeuo pipefail
# shellcheck source=./base_image_type.sh
source "${PIPELINE_REPO_DIR}/stages/scanning/openscap/base_image_type.sh"
mkdir -p "${OSCAP_SCANS}"
echo "${DOCKER_IMAGE_PATH}"
OSCAP_VERSION=$(cat "${PIPELINE_REPO_DIR}"/stages/scanning/rhel-oscap-version.json | jq .version | sed -e 's/"//g')
oscap_container=$(python3 "${PIPELINE_REPO_DIR}/stages/scanning/openscap/compliance.py" --oscap-version "${OSCAP_VERSION}" --image-type "${BASE_IMAGE_TYPE}" | sed s/\'/\"/g)
echo "${oscap_container}"
SCAP_CONTENT="scap-content"
mkdir -p "${SCAP_CONTENT}"

if [[ "${BASE_IMAGE_TYPE}" == "ubuntu1604-container" ]]; then
  curl -L "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_16-04_LTS_V2R2_STIG_SCAP_1-2_Benchmark.zip" -o "${SCAP_CONTENT}/scap-security-guide.zip"
elif [[ "${BASE_IMAGE_TYPE}" == "ubuntu1804-container" ]]; then
  curl -L "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_18-04_V2R1_STIG_SCAP_1-2_Benchmark.zip" -o "${SCAP_CONTENT}/scap-security-guide.zip"
else
  curl -L "https://github.com/ComplianceAsCode/content/releases/download/v${OSCAP_VERSION}/scap-security-guide-${OSCAP_VERSION}.zip" -o "${SCAP_CONTENT}/scap-security-guide.zip"
fi

unzip -qq -o "${SCAP_CONTENT}/scap-security-guide.zip" -d "${SCAP_CONTENT}"
profile=$(echo "${oscap_container}" | grep -o '"profile": "[^"]*' | grep -o '[^"]*$')
securityGuide=$(echo "${oscap_container}" | grep -o '"securityGuide": "[^"]*' | grep -o '[^"]*$')
echo "profile: ${profile}"
echo "securityGuide: ${securityGuide}"
oscap-podman "${DOCKER_IMAGE_PATH}" xccdf eval --verbose ERROR --fetch-remote-resources --profile "${profile}" --report report.html "${SCAP_CONTENT}/${securityGuide}" || true
ls report.html
rm -rf "${SCAP_CONTENT}"
echo "${OSCAP_VERSION}" >>"${OSCAP_SCANS}/oscap-version.txt"
cp report.html "${OSCAP_SCANS}/report.html"

echo "OSCAP_COMPLIANCE_URL=${CI_JOB_URL}" >oscap-compliance.env

cat oscap-compliance.env
