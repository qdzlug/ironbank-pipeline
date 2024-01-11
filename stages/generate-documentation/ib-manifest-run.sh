#!/bin/bash
set -Eeuo pipefail

GPG_VERSION=$(gpg --version | grep '(?<=gpg .GnuPG.)([^0-9]+)([0-9]+[.][0-9]+[.][0-9]+)' -oP | sed -E 's/ //g')

# Create manifest.json
export GPG_VERSION

jq -n '
{
  "critical": {
    "type": "atomic container signature",
    "image": {
      "podman-manifest-digest": env.DIGEST_TO_SCAN
    },
    "identity": {
      "podman-reference": env.IMAGE_TO_SCAN
    }
  },
  "optional": {
    "creator": env.GPG_VERSION
  }
}' >"${ARTIFACT_DIR}/reports/manifest.json"
cat "${ARTIFACT_DIR}/reports/manifest.json"
