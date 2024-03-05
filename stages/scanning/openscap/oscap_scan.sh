#!/bin/bash

set -euo pipefail

OSCAP_PROFILE=$(python3 "${PIPELINE_REPO_DIR}/stages/scanning/openscap/oscap_profiler.py" "${OS_TYPE}")

# if OS_TYPE has a 'none' OSCAP_PROFILE, exit gracefully
if [ "$OSCAP_PROFILE" = '{"oval": "none", "profile": "none", "securityGuide": "none", "scanner": "none"}' ]; then
  echo "INFO 'oscap_profiler.py ${OS_TYPE}' returned '${OSCAP_PROFILE}' nothing to do"
  exit 0
else
  echo "INFO 'oscap_profiler.py ${OS_TYPE}' returned '${OSCAP_PROFILE}' begin scan"
fi

OVAL=$(echo "${OSCAP_PROFILE}" | grep -o '"oval": "[^"]*' | grep -o '[^"]*$')
PROFILE=$(echo "${OSCAP_PROFILE}" | grep -o '"profile": "[^"]*' | grep -o '[^"]*$')
SECURITY_GUIDE=$(echo "${OSCAP_PROFILE}" | grep -o '"securityGuide": "[^"]*' | grep -o '[^"]*$')
SCANNER=$(echo "${OSCAP_PROFILE}" | grep -o '"scanner": "[^"]*' | grep -o '[^"]*$')

# if OVAL fetch from ci-files
if [ "$OVAL" = 'none' ]; then
  echo "INFO no oval, skipping"
else
  echo "INFO oval $OVAL, retrieving"
  aws s3 cp --quiet s3://${CI_FILES_BUCKET}/gitlab-runner-dsop-privileged/oscap/"$OSCAP_OVAL" /opt/oscap/"$OSCAP_OVAL"
fi

# scan artifact(s)
mkdir -p "${CI_PROJECT_DIR}"/"${OSCAP_SCANS}"
cp /opt//oscap/version.txt "${CI_PROJECT_DIR}/${OSCAP_SCANS}/oscap-version.txt"

# env artifact(s)
echo "OSCAP_COMPLIANCE_URL=${CI_JOB_URL}" >"${CI_PROJECT_DIR}/oscap-compliance.env"
chmod 644 "${CI_PROJECT_DIR}/oscap-compliance.env"

# auth
mkdir -p /run/containers/0
cp "${DOCKER_AUTH_FILE_PULL}" /run/containers/0/auth.json

# if redhat, natively scan
if [ "${SCANNER}" = 'redhat' ]; then
  echo "INFO performing scan"
  /usr/local/bin/oscap-podman "${IMAGE_TO_SCAN}" \
    xccdf \
    eval \
    --verbose ERROR \
    --profile "${PROFILE}" \
    --stig-viewer "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report_stigviewer.xml" \
    --results "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report.xml" \
    --report "${CI_PROJECT_DIR}/${OSCAP_SCANS}/report.html" \
    --local-files /opt/oscap/ \
    /opt/oscap/scap-security-guide/"${SECURITY_GUIDE}" || true

# if debian/suse, use a scanner pod
else
  # load the scanner
  echo "INFO loading scanner"
  podman load -q -i "/opt/oscap/$SCANNER.tar" >/dev/null

  # save the target, scanners may not have ca certs
  echo "INFO pulling target"
  podman pull "${IMAGE_TO_SCAN}"
  echo "INFO saving target"
  podman image save -q -o /opt/oscap/target.tar "${IMAGE_TO_SCAN}"

  # sleep
  podman run \
    -e CONTAINER_STORAGE=vfs \
    --detach \
    --privileged \
    --name scanner \
    -v /usr/local/bin/oscap-podman:/usr/local/bin/oscap-podman \
    -v "${CI_PROJECT_DIR}/${OSCAP_SCANS}":"${CI_PROJECT_DIR}/${OSCAP_SCANS}" \
    -v "${DOCKER_AUTH_FILE_PULL}":/run/containers/0/auth.json \
    -v /opt:/opt \
    "ib-oscap-${SCANNER}:1.0.0" sleep 900

  # load the saved target
  echo "INFO scanner load target"
  podman exec scanner podman load -q -i /opt/oscap/target.tar >/dev/null

  # scanner scan target
  echo "INFO performing scan"
  podman exec scanner /usr/local/bin/oscap-podman "${IMAGE_TO_SCAN}" \
    xccdf \
    eval \
    --verbose ERROR \
    --profile "${PROFILE}" \
    --stig-viewer "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report_stigviewer.xml" \
    --results "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report.xml" \
    --report "${CI_PROJECT_DIR}/${OSCAP_SCANS}/report.html" \
    --local-files /opt/oscap/ \
    /opt/oscap/scap-security-guide/"${SECURITY_GUIDE}" || true
fi

# IMPORTANT oscap-podman completes successfully with a nonzero RC, hence '|| true' ..
# or it may segfault before producing artifacts, so test
if
  [ -f "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report_stigviewer.xml" ] &&
    [ -f "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report.xml" ] &&
    [ -f "${CI_PROJECT_DIR}/${OSCAP_SCANS}/report.html" ]
then
  echo "INFO scan complete"
else
  echo "ERROR scan artifacts missing!"
  exit 1
fi
