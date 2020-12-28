#!/bin/bash
set -Eeuo pipefail
# Check if required files exist
# Testing with `-f` avoids the scenario where a malicious symlink is is named `README` in the repository
if ! [[ -f README.md ]]; then
  echo "README.md not found"
  exit 1
fi
if ! [[ -f Dockerfile ]]; then
  echo "Dockerfile not found"
  exit 1
fi
if ! [[ -f "LICENSE" ]]; then
  echo "LICENSE not found"
  exit 1
fi

# test for CLAMAV_WHITELIST CI variable existence and clamav-whitelist file existence
# exits if the CI varible CLAMAV_WHITELIST exists but a whitelist file named clamav-whitelist is not found
if [[ "${CLAMAV_WHITELIST:-}" ]] && ! [[ -f "clamav-whitelist" ]]; then
  echo "CLAMAV_WHITELIST CI variable exists but clamav-whitelist file not found"
  exit 1
fi

# test for clamav-whitelist and no CLAMAV_WHITELIST CI varaible
# exits if a `clamav-whitelist` file is found, but there is no CLAMAV_WHITELIST CI variable
if [[ -f "clamav-whitelist" ]] && [[ -z "${CLAMAV_WHITELIST:-}" ]]; then
  echo "clamav-whitelist file found but CLAMAV_WHITELIST CI variable does not exist"
  exit 1
fi
