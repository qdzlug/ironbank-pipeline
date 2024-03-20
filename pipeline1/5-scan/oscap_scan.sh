#!/bin/bash

set -euo pipefail

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
  aws s3 cp --quiet s3://"${CI_FILES_BUCKET}"/gitlab-runner-dsop-privileged/oscap/"$OSCAP_OVAL" /opt/oscap/"$OSCAP_OVAL"
fi

# setup auth
mkdir -p /run/containers/0
cp "${DOCKER_AUTH_FILE_PULL}" /run/containers/0/auth.json

for SCAN_LOGIC_DIR in "$ARTIFACT_STORAGE/scan-logic"/*; do

  # IMAGE_TO_SCAN
  URI_BASENAME=$(awk -F'=' '/IMAGE_TO_SCAN/ { print $2 }' "$SCAN_LOGIC_DIR/scan_logic.env" | awk -F':' '{ print $1 }')
  URI_DIGEST=$(awk -F'=' '/DIGEST_TO_SCAN/ { print $2 }' "$SCAN_LOGIC_DIR/scan_logic.env")

  # amd64, arm64, ..
  PLATFORM=$(basename "$SCAN_LOGIC_DIR")

  # setup platform artifact(s)
  ARTIFACT_DIR_REALPATH=$(realpath "${ARTIFACT_DIR}/${PLATFORM}")
  mkdir -p "${ARTIFACT_DIR_REALPATH}"

  # if no scanner, scan natively
  if [ -z "${OSCAP_SCANNER:-}" ]; then
    echo "INFO begin native scan"
    /usr/local/bin/oscap-podman "${URI_BASENAME}@${URI_DIGEST}" \
      xccdf \
      eval \
      --verbose ERROR \
      --profile "${OSCAP_PROFILE}" \
      --stig-viewer "${ARTIFACT_DIR_REALPATH}/compliance_output_report_stigviewer.xml" \
      --results "${ARTIFACT_DIR_REALPATH}/compliance_output_report.xml" \
      --report "${ARTIFACT_DIR_REALPATH}/report.html" \
      --local-files /opt/oscap/ \
      /opt/oscap/scap-security-guide/"${OSCAP_DATASTREAM}" || true

  # if debian/suse, use a scanner pod
  else
    # load the scanner

    if podman image ls | grep -q "ib-oscap-$OSCAP_SCANNER"; then
      echo "INFO non-native scan $OSCAP_SCANNER, loaded"
    else
      echo "INFO non-native scan $OSCAP_SCANNER, loading"
      podman load -q -i "/opt/oscap/$OSCAP_SCANNER.tar" >/dev/null
    fi

    # save the target, scanner may not have ca certs
    rm -f /opt/oscap/target.tar
    skopeo copy docker://"${URI_BASENAME}@${URI_DIGEST}" docker-archive:/opt/oscap/target.tar

    # start detached scanner
    podman run \
      -e CONTAINER_STORAGE=vfs \
      --detach \
      --privileged \
      --name scanner \
      -v /usr/local/bin/oscap-podman:/usr/local/bin/oscap-podman \
      -v "${ARTIFACT_DIR_REALPATH}":"${ARTIFACT_DIR_REALPATH}" \
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
      --stig-viewer "${ARTIFACT_DIR_REALPATH}/compliance_output_report_stigviewer.xml" \
      --results "${ARTIFACT_DIR_REALPATH}/compliance_output_report.xml" \
      --report "${ARTIFACT_DIR_REALPATH}/report.html" \
      --local-files /opt/oscap/ \
      /opt/oscap/scap-security-guide/"${OSCAP_DATASTREAM}" || true
  fi

  # IMPORTANT oscap-podman completes successfully with a nonzero RC, hence '|| true' ..
  # or it may segfault before producing artifacts, so test
  if
    [ -f "${ARTIFACT_DIR_REALPATH}/compliance_output_report_stigviewer.xml" ] &&
      [ -f "${ARTIFACT_DIR_REALPATH}/compliance_output_report.xml" ] &&
      [ -f "${ARTIFACT_DIR_REALPATH}/report.html" ]
  then
    echo "INFO scan complete"
  else
    echo "ERROR scan artifacts missing!"
    exit 1
  fi

  # cleanup
  podman rm -f scanner || true
done
