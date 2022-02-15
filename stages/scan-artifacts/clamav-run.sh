#!/bin/bash
set -Eeuo pipefail
shopt -s nullglob # Allow import-artifacts/*/* to match nothing

# Install clamav definitions from av-updater using freshclam
DEFPATH=/clamav/definitions
curl -L --header "DEPLOY-TOKEN: ${IB_TOOLS_REPO_READ}" "${CI_SERVER_URL}/ironbank-tools/av-updater/-/jobs/artifacts/master/raw/definitions.tar.gz?job=build" -o definitions.tar.gz
tar -C /clamav/definitions/ -xzvf definitions.tar.gz

# Verify existence of expected files
if [[ -f "${DEFPATH}/bytecode.cvd" ]] && [[ -f "${DEFPATH}/daily.cvd" || -f "${DEFPATH}/daily.cld" ]] && [[ -f "${DEFPATH}/main.cvd" || -f "${DEFPATH}/main.cld" ]]; then
  echo "clamav definitions successfully installed."
  echo "clamscan --version"
  clamscan --version
else
  echo "ERROR: clamav definitions did not install"
  exit 1
fi

if [[ "${CLAMAV_WHITELIST_DSOP:-}" ]]; then
  echo "${CLAMAV_WHITELIST_DSOP}" >/clamav/definitions/clamav_whitelist.ign2
fi

if [[ "${CLAMAV_WHITELIST_PROJECT:-}" ]]; then
  echo "${CLAMAV_WHITELIST_PROJECT}" >>/clamav/definitions/clamav_whitelist.ign2
fi

if [[ "${CLAMAV_WHITELIST:-}" ]]; then
  # Must be added to file last, the file from inside the repo may lack a trailing newline.
  # TODO: phase out and remove in-repo "clamav-whitelist"
  cat "clamav-whitelist" >>/clamav/definitions/clamav_whitelist.ign2
fi

clamscan -irv --max-filesize=4000M --max-scansize=4000M "${ARTIFACT_STORAGE}"/import-artifacts | tee -a "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
