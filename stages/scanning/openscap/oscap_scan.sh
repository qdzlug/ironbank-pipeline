#!/bin/bash

set -euo pipefail

python3 "${PIPELINE_REPO_DIR}/stages/scanning/openscap/oscap_profiler.py" "${OS_TYPE}"
source oscap_profile.txt

# check OSCAP_DATASTREAM
if [ -n "${OSCAP_DATASTREAM:-}" ]; then
  echo "INFO found datastream $OSCAP_DATASTREAM"
else
  echo "INFO no datastream, nothing to do."
  exit 0
fi

# check OSCAP_OVAL retrieve from CI_FILES_BUCKET
if [ -n "${OSCAP_OVAL:-}" ]; then
  echo "INFO found oval $OSCAP_OVAL, retrieving"
  python3 -c "import boto3; boto3.resource('s3').meta.client.download_file('${CI_FILES_BUCKET}', 'gitlab-runner-dsop-privileged/oscap/${OSCAP_OVAL}', '/opt/oscap/${OSCAP_OVAL}')"
fi

# setup artifact(s)
mkdir -p "${CI_PROJECT_DIR}"/"${OSCAP_SCANS}"
cp /opt/oscap/version.txt "${CI_PROJECT_DIR}/${OSCAP_SCANS}/oscap-version.txt"
echo "OSCAP_COMPLIANCE_URL=${CI_JOB_URL}" >"${CI_PROJECT_DIR}/oscap-compliance.env"
chmod 644 "${CI_PROJECT_DIR}/oscap-compliance.env"

# setup auth
mkdir -p /run/containers/0
cp "${DOCKER_AUTH_FILE_PULL}" /run/containers/0/auth.json

# if no scanner, scan natively
if [ -z "${OSCAP_SCANNER:-}" ]; then
  echo "INFO begin native scan"
  /usr/local/bin/oscap-podman "${IMAGE_TO_SCAN}" \
    xccdf \
    eval \
    --verbose ERROR \
    --profile "${OSCAP_PROFILE}" \
    --stig-viewer "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report_stigviewer.xml" \
    --results "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report.xml" \
    --report "${CI_PROJECT_DIR}/${OSCAP_SCANS}/report.html" \
    --local-files /opt/oscap/ \
    /opt/oscap/scap-security-guide/"${OSCAP_DATASTREAM}" || true

# if debian/suse, use a scanner pod
else
  # load the scanner
  echo "INFO non-native scan $OSCAP_SCANNER, loading"
  podman load -q -i "/opt/oscap/$OSCAP_SCANNER.tar" >/dev/null

  # save the target, scanner may not have ca certs
  skopeo copy docker://"${IMAGE_TO_SCAN}" docker-archive:/opt/oscap/target.tar

  # start detached scanner
  podman run \
    -e CONTAINER_STORAGE=vfs \
    --detach \
    --privileged \
    --name scanner \
    -v /usr/local/bin/oscap-podman:/usr/local/bin/oscap-podman \
    -v "${CI_PROJECT_DIR}/${OSCAP_SCANS}":"${CI_PROJECT_DIR}/${OSCAP_SCANS}" \
    -v "${DOCKER_AUTH_FILE_PULL}":/run/containers/0/auth.json \
    -v /opt:/opt \
    "ib-oscap-${OSCAP_SCANNER}:1.0.0" sleep 900

  # scanner load target
  echo "INFO loading target"
  TARGET_SHA=$(podman exec scanner podman load -q -i /opt/oscap/target.tar 2>/dev/null | awk '/sha256/ { print $3 }')

  # scanner scan target
  echo "INFO begin ${OSCAP_SCANNER} scan"
  podman exec scanner /usr/local/bin/oscap-podman "${TARGET_SHA}" \
    xccdf \
    eval \
    --verbose ERROR \
    --profile "${OSCAP_PROFILE}" \
    --stig-viewer "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report_stigviewer.xml" \
    --results "${CI_PROJECT_DIR}/${OSCAP_SCANS}/compliance_output_report.xml" \
    --report "${CI_PROJECT_DIR}/${OSCAP_SCANS}/report.html" \
    --local-files /opt/oscap/ \
    /opt/oscap/scap-security-guide/"${OSCAP_DATASTREAM}" || true
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
