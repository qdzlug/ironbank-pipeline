#!/bin/bash
set -Eeuo pipefail
shopt -s nullglob # Allow import-artifacts/*/* to match nothing

## download definitions.tar.gz from storage artifcat registry
## curl -o definitions.tar.gz --header "JOB-TOKEN:${CI_JOB_TOKEN}" "https://code.il2.dso.mil/api/v4/projects/${CI_PROJECT_ID}/packages/generic/clamav/definitions.tar.gz"
tar -C /clamav/definitions/ -xzvf definitions.tar.gz

if [[ -f "$DEFPATH/bytecode.cvd" ]] && [[ -f "$DEFPATH/daily.cvd" ]] && [[ -f "$DEFPATH/main.cvd" ]]; then
  echo "clamav definitions successfully imported."
  echo "clamav definitions version: $(clamscan --version | cut -d/ -f3)"
else
  echo "ERROR: clamav definitions did not import"
  exit 1
fi

if [[ "${CLAMAV_WHITELIST:-}" ]]; then
  cp "clamav-whitelist" /usr/local/share/clamav/clamav_whitelist.ign2
fi

for filename in "${ARTIFACT_STORAGE}"/import-artifacts/*/*; do
  # TODO: fix or temporarily skip scans of large files
  clamscan -irv --max-filesize=4000M --max-scansize=4000M "${filename}" | tee -a "${ARTIFACT_DIR}/import-artifacts-clamav-report.txt"
done
