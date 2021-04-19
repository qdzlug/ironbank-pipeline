#!/bin/bash
set -Eeuo pipefail

echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key
mkdir -p "${ARTIFACT_DIR}"

GPG_VERSION=$(gpg --version | grep '(?<=gpg .GnuPG.)([^0-9]+)([0-9]+[.][0-9]+[.][0-9]+)' -oP | sed -E 's/ //g')

# Create manifest.json
export PODMAN_REFERENCE="${STAGING_REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_VERSION}"
export GPG_VERSION

jq -n '
{
  "critical": {
    "type": "atomic container signature",
    "image": {
      "podman-manifest-digest": env.IMAGE_PODMAN_SHA,
      "image-tar-sha256-checksum": env.IMAGE_TAR_SHA
    },
    "identity": {
      "podman-reference": env.PODMAN_REFERENCE
    }
  },
  "optional": {
    "creator": env.GPG_VERSION
  }
}' >"${ARTIFACT_DIR}/manifest.json"
cat "${ARTIFACT_DIR}/manifest.json"

# Sign manifest.json
gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
echo "pinentry-mode loopback" >>"${HOME}"/.gnupg/gpg.conf
gpg --detach-sign -o "${SIG_FILE}.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" manifest.json

# Stage manifest for upload
mv manifest.json "${SIG_FILE}.sig" "${ARTIFACT_DIR}"
