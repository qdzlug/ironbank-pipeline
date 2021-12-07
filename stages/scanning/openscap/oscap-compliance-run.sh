#!/bin/bash
set -Eeuo pipefail
# shellcheck source=./stages/scanning/openscap/base_image_type.sh
source "${PIPELINE_REPO_DIR}/stages/scanning/openscap/base_image_type.sh"
echo "Imported Base Image Type: ${BASE_IMAGE_TYPE}"
mkdir -p "${OSCAP_SCANS}"
echo "${DOCKER_IMAGE_PATH}"

# If OSCAP_VERSION variable doesn't exist, create the variable
if [[ -z ${OSCAP_VERSION:-} ]]; then
  OSCAP_VERSION=$(jq -r .version "$PIPELINE_REPO_DIR/stages/scanning/rhel-oscap-version.json" | sed 's/v//g')
fi

oscap_container=$(python3 "${PIPELINE_REPO_DIR}/stages/scanning/openscap/compliance.py" --oscap-version "${OSCAP_VERSION}" --image-type "${BASE_IMAGE_TYPE}" | sed s/\'/\"/g)
echo "${oscap_container}"
SCAP_CONTENT="scap-content"
mkdir -p "${SCAP_CONTENT}"

# If SCAP_URL var exists, use this to download scap content, else retrieve it based on BASE_IMAGE_TYPE
if [[ -n ${SCAP_URL:-} ]]; then
  curl -L "${SCAP_UR}" -o "${SCAP_CONTENT}/scap-security-guide.zip"
elif [[ "${BASE_IMAGE_TYPE}" == "ubuntu1604-container" ]]; then
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
oscap-podman "${DOCKER_IMAGE_PATH}" xccdf eval --verbose ERROR --fetch-remote-resources --profile "${profile}" --results compliance_output_report.xml --report report.html "${SCAP_CONTENT}/${securityGuide}" || true
ls compliance_output_report.xml
ls report.html
rm -rf "${SCAP_CONTENT}"
echo "${OSCAP_VERSION}" >>"${OSCAP_SCANS}/oscap-version.txt"
cp report.html "${OSCAP_SCANS}/report.html"
cp compliance_output_report.xml "${OSCAP_SCANS}/compliance_output_report.xml"

echo "OSCAP_COMPLIANCE_URL=${CI_JOB_URL}" >oscap-compliance.env

cat oscap-compliance.env
