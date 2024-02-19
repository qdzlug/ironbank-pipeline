#!/bin/bash

set -euo pipefail

OSCAP_PROFILE=$(python3 "${PIPELINE_REPO_DIR}/stages/scanning/openscap/oscap_profiler.py" "${OS_TYPE}")

# if OS_TYPE has a 'none' OSCAP_PROFILE, exit gracefully
if [ "$OSCAP_PROFILE" = '{"profile": "none", "securityGuide": "none", "scanner": "none"}' ]; then
  echo "INFO: 'oscap_profiler.py ${OS_TYPE}' returned '${OSCAP_PROFILE}' nothing to do"
  exit 0
else
  echo "INFO: 'oscap_profiler.py ${OS_TYPE}' returned '${OSCAP_PROFILE}' begin scan"
fi

PROFILE=$(echo "${OSCAP_PROFILE}" | grep -o '"profile": "[^"]*' | grep -o '[^"]*$')
SECURITY_GUIDE=$(echo "${OSCAP_PROFILE}" | grep -o '"securityGuide": "[^"]*' | grep -o '[^"]*$')
SCANNER=$(echo "${OSCAP_PROFILE}" | grep -o '"scanner": "[^"]*' | grep -o '[^"]*$')
REPORT_DIR="${CI_PROJECT_DIR}/${OSCAP_SCANS}"

# if redhat, natively scan
if [ "${SCANNER}" = 'redhat' ]; then
  mkdir -p /run/containers/0
  cp "${DOCKER_AUTH_FILE_PULL}" /run/containers/0/auth.json
  /opt/oscap-podman "${IMAGE_TO_SCAN}" \
        xccdf \
        eval \
        --verbose ERROR \
        --profile "${PROFILE}" \
        --stig-viewer ${REPORT_DIR}/compliance_output_report_stigviewer.xml \
        --results ${REPORT_DIR}/compliance_output_report.xml \
        --report ${REPORT_DIR}/report.html \
        --local-files /opt/ \
        /opt/scap-security-guide/"${SECURITY_GUIDE}"

# if debian/suse, use a scanner pod
else
  podman load -q -i "/opt/$SCANNER.tar" > /dev/null
  podman run \
    --detach \
    --privileged \
    --name scanner \
    -v /opt:/opt \
    -v "${REPORT_DIR}":"${REPORT_DIR}" \
    -v "${DOCKER_AUTH_FILE_PULL}":/run/containers/0/auth.json \
    "ib-oscap-${SCANNER}:0.1" sleep 900
  podman exec scanner podman pull "${IMAGE_TO_SCAN}"
  podman exec scanner /opt/oscap-podman "${IMAGE_TO_SCAN}" \
        xccdf \
        eval \
        --verbose ERROR \
        --profile "${PROFILE}" \
        --stig-viewer ${REPORT_DIR}/compliance_output_report_stigviewer.xml \
        --results ${REPORT_DIR}/compliance_output_report.xml \
        --report ${REPORT_DIR}/report.html \
        --local-files /opt/ \
        /opt/scap-security-guide/"${SECURITY_GUIDE}"
fi

# etc
cp /opt/oscap-version.txt "${REPORT_DIR}/oscap-version.txt"
echo "OSCAP_COMPLIANCE_URL=${CI_JOB_URL}" > oscap-compliance.env
