#!/bin/bash
set -Eeuo pipefail
shopt -s nullglob # Allow import-artifacts/*/* to match nothing

# Install clamav definitions from av-updater using freshclam
DEFPATH=/clamav/definitions
curl -L --header "DEPLOY-TOKEN: ${IB_TOOLS_REPO_READ}" "https://repo1.dso.mil/ironbank-tools/av-updater/-/jobs/artifacts/switch-to-generate-def-tar/raw/definitions.tar.gz?job=build" -o definitions.tar.gz
tar -C /clamav/definitions/ -xzvf definitions.tar.gz

# Verify existence of expected files
if [[ -f "$DEFPATH/bytecode.cvd" ]] && [[ -f "$DEFPATH/daily.cvd" ]] && [[ -f "$DEFPATH/main.cvd" ]]; then
  echo "clamav definitions successfully installed."
  clamav_definitions_version="$(clamscan --version | cut -d/ -f3)"
  echo "clamav definitions version: $clamav_definitions_version"
else
  echo "ERROR: clamav definitions did not install"
  exit 1
fi

if [[ "${CLAMAV_WHITELIST:-}" ]]; then
  cp "clamav-whitelist" /usr/local/share/clamav/clamav_whitelist.ign2
fi

for filename in "${ARTIFACT_STORAGE}"/import-artifacts/*/*; do
  # TODO: fix or temporarily skip scans of large files
  clamscan -irv --max-filesize=4000M --max-scansize=4000M "${filename}" | tee -a "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
done
