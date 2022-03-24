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

# Fails the pipeline if a trufflehog.yaml file is in the root of the project
if [[ -f "trufflehog.yaml" ]]; then
  echo "ERROR: trufflehog.yaml file is not permitted to exist in repo"
  exit 1
fi

# test for trufflehog-config.yaml and no TRUFFLEHOG_CONFIG CI varaible
# exits if a `trufflehog-config.yaml` file is found, but there is no TRUFFLEHOG_CONFIG CI variable
if [[ -f "trufflehog-config.yaml" || -f "trufflehog-config.yml" ]] && [[ -z "${TRUFFLEHOG_CONFIG:-}" ]]; then
  echo "trufflehog-config file found but TRUFFLEHOG_CONFIG CI variable does not exist"
  exit 1
fi

# Check if hardening_manifest.yaml exists
if [[ -f hardening_manifest.yaml ]]; then
  echo "hardening_manifest.yaml found!"
else
  echo "hardening_maifest.yaml not found, please add one to this repo"
  exit 1
fi

# Check for Jenkinsfile
if [[ -f Jenkinsfile ]]; then
  echo "Jenkinsfile found, please remove this file before rerunning your pipeline"
  exit 1
fi

# Check for deprecated download.yaml and download.json file
if [[ -f download.yaml || -f download.json ]]; then
  echo "download.yaml found, this file is deprecated please add hardening_manifest.yaml file before rerunning your pipeline"
  exit 1
fi

# Check for labels in the Dockerfile
if grep -i -q '\s*LABEL' Dockerfile; then
  echo "LABEL found in Dockerfile, move all LABELs to the hardening_manifest.yaml file"
  exit 1
fi
