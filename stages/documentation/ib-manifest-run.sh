#!/bin/bash
set -Eeuo pipefail

GPG_VERSION=$(gpg --version | grep '(?<=gpg .GnuPG.)([^0-9]+)([0-9]+[.][0-9]+[.][0-9]+)' -oP | sed -E 's/ //g')

# Create manifest.json
export PODMAN_REFERENCE="${REGISTRY_URL_STAGING}/${IMAGE_NAME}:${IMAGE_VERSION}"
export GPG_VERSION

jq -n '
{
  "critical": {
    "type": "atomic container signature",
    "image": {
      "podman-manifest-digest": env.IMAGE_PODMAN_SHA
    },
    "identity": {
      "podman-reference": env.PODMAN_REFERENCE
    }
  },
  "optional": {
    "creator": env.GPG_VERSION
  }
}' >"${ARTIFACT_DIR}/reports/manifest.json"
cat "${ARTIFACT_DIR}/reports/manifest.json"
