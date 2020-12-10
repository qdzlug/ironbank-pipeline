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
