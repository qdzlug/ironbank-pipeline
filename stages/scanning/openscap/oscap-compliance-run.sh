#!/bin/bash

if [[ -n ${SKIP_OPENSCAP:-} ]]; then
  echo "Skipping OpenSCAP scan"
  exit 0
fi

set -Eeuo pipefail
echo "Imported Base Image Type: ${BASE_IMAGE_TYPE}"
mkdir -p "${OSCAP_SCANS}"
podman pull --authfile "${DOCKER_AUTH_FILE_PULL}" "${IMAGE_TO_SCAN}"
set -x
DOCKER_IMAGE_PATH=$(podman images -q)
export DOCKER_IMAGE_PATH
echo "${DOCKER_IMAGE_PATH}"

oscap_container=$(python3 "${PIPELINE_REPO_DIR}/stages/scanning/openscap/compliance.py" --oscap-version "${OSCAP_VERSION}" --image-type "${BASE_IMAGE_TYPE}" | sed s/\'/\"/g)
echo "${oscap_container}"
export SCAP_CONTENT
mkdir -p "${SCAP_CONTENT}"

# If SCAP_URL var exists, use this to download scap content, else retrieve it based on BASE_IMAGE_TYPE
if [[ -f "${SCAP_CONTENT}/scap-security-guide-${OSCAP_VERSION}.zip" ]]; then
  echo "File retrieved from cache"
else
  if [[ -n ${SCAP_URL:-} ]]; then
    curl -L "${SCAP_URL}" -o "${SCAP_CONTENT}/scap-security-guide-${OSCAP_VERSION}.zip"
  else
    curl -L "https://github.com/ComplianceAsCode/content/releases/download/v${OSCAP_VERSION}/scap-security-guide-${OSCAP_VERSION}.zip" -o "${SCAP_CONTENT}/scap-security-guide-${OSCAP_VERSION}.zip"
  fi
fi

unzip -qq -o "${SCAP_CONTENT}/scap-security-guide-${OSCAP_VERSION}.zip" -d "${SCAP_CONTENT}"
profile=$(echo "${oscap_container}" | grep -o '"profile": "[^"]*' | grep -o '[^"]*$')
securityGuide=$(echo "${oscap_container}" | grep -o '"securityGuide": "[^"]*' | grep -o '[^"]*$')
export securityGuide
echo "profile: ${profile}"
echo "securityGuide: ${securityGuide}"

case "${securityGuide}" in
  *ssg-sle15*)
    echo "Limiting scanning to SLE Server patches"
    sed -i -e 's,/security/oval/suse\.linux\.enterprise\.15\.xml,/security/oval/suse.linux.enterprise.server.15-patch.xml,' "${SCAP_CONTENT}/${securityGuide}"
    ;;
esac

python3 "${PIPELINE_REPO_DIR}/stages/scanning/openscap/fix_ubi_oval_url.py"

oscap-podman "${DOCKER_IMAGE_PATH}" xccdf eval --verbose ERROR --fetch-remote-resources --profile "${profile}" --stig-viewer compliance_output_report_stigviewer.xml --results compliance_output_report.xml --report report.html "${SCAP_CONTENT}/${securityGuide}" || true
ls compliance_output_report.xml compliance_output_report_stigviewer.xml report.html
echo "${OSCAP_VERSION}" >>"${OSCAP_SCANS}/oscap-version.txt"
cp report.html "${OSCAP_SCANS}/report.html"
cp compliance_output_report.xml "${OSCAP_SCANS}/compliance_output_report.xml"
cp compliance_output_report_stigviewer.xml "${OSCAP_SCANS}/compliance_output_report_stigviewer.xml"

echo "OSCAP_COMPLIANCE_URL=${CI_JOB_URL}" >oscap-compliance.env

cat oscap-compliance.env
