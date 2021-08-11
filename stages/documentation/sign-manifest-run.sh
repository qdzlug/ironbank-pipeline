#!/bin/bash
set -Eeuo pipefail

echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key

GPG_VERSION=$(gpg --version | grep '(?<=gpg .GnuPG.)([^0-9]+)([0-9]+[.][0-9]+[.][0-9]+)' -oP | sed -E 's/ //g')

# Create manifest.json
export PODMAN_REFERENCE="${STAGING_REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_VERSION}"
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

# Sign manifest.json
gpg --import --batch --pinentry-mode loopback --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
gpg --detach-sign -o "${ARTIFACT_DIR}/reports/${SIG_FILE}.sig" --armor --yes --batch --pinentry-mode loopback --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" "${ARTIFACT_DIR}/reports/manifest.json"
