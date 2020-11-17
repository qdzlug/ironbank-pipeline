#!/bin/bash
set -Eeuo pipefail
mkdir -p "${OSCAP_SCANS}"
DOCKER_IMAGE_PATH=$(podman load -i "${ARTIFACT_STORAGE}"/build/"${CI_PROJECT_NAME}"-"${IMG_VERSION}".tar | awk '{print $3}')
echo "${DOCKER_IMAGE_PATH}"
OSCAP_VERSION=$(curl -fsSLI -o /dev/null -w "%{url_effective}" https://github.com/ComplianceAsCode/content/releases/latest | grep -Eo "[0-9\\.]+$" | awk '{$1=$1};1')
base_image_type=$(podman inspect -f '{{index .Labels "com.redhat.component"}}' "${DOCKER_IMAGE_PATH}")

if [[ "${base_image_type}" == "" ]]; then
  base_image_type=$(podman inspect -f '{{index .Labels "os_type"}}' "${DOCKER_IMAGE_PATH}")
  if [[ "${base_image_type}" == "" ]]; then
    labels=$(podman inspect -f '{{index .Labels}}' "${DOCKER_IMAGE_PATH}")
    echo "Unknown image type. Can't choose security guide. labels: ${labels}"
    exit 1
  fi
fi
oscap_container=$(python3 "${PIPELINE_REPO_DIR}/stages/scanning/compliance.py" --oscap-version "${OSCAP_VERSION}" --image-type "${base_image_type}" | sed s/\'/\"/g)
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
