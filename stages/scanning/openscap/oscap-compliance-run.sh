#!/bin/bash
set -Eeuo pipefail
mkdir -p "${OSCAP_SCANS}"
echo "${DOCKER_IMAGE_PATH}"
OSCAP_VERSION=$(cat "${PIPELINE_REPO_DIR}"/stages/scanning/rhel-oscap-version.json | jq .version | sed -e 's/"//g')
oscap_container=$(python3 "${PIPELINE_REPO_DIR}/stages/scanning/openscap/compliance.py" --oscap-version "${OSCAP_VERSION}" --image-type "${BASE_IMAGE_TYPE}" | sed s/\'/\"/g)
echo "${oscap_container}"
curl -L "https://github.com/ComplianceAsCode/content/releases/download/v${OSCAP_VERSION}/scap-security-guide-${OSCAP_VERSION}.zip" -o scap-security-guide.zip
unzip -qq -o scap-security-guide.zip

profile=$(echo "${oscap_container}" | grep -o '"profile": "[^"]*' | grep -o '[^"]*$')
securityGuide=$(echo "${oscap_container}" | grep -o '"securityGuide": "[^"]*' | grep -o '[^"]*$')
echo "profile: ${profile}"
echo "securityGuide: ${securityGuide}"
oscap-podman "${DOCKER_IMAGE_PATH}" xccdf eval --verbose ERROR --fetch-remote-resources --profile "${profile}" --report report.html "${securityGuide}" || true
ls report.html
rm -rf "scap-security-guide.zip scap-security-guide-${OSCAP_VERSION}"
echo "${OSCAP_VERSION}" >>"${OSCAP_SCANS}/oscap-version.txt"
cp report.html "${OSCAP_SCANS}/report.html"

echo "OSCAP_COMPLIANCE_URL=${CI_JOB_URL}" >oscap-compliance.env

cat oscap-compliance.env
