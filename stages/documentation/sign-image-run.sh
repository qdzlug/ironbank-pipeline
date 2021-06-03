#!/bin/bash
set -Eeuo pipefail

echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key

gpg --import --batch --pinentry-mode loopback --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
gpg --detach-sign -o "${ARTIFACT_DIR}/reports/${IMAGE_FILE}.tar.sig" --armor --yes --batch --pinentry-mode loopback --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" "${ARTIFACT_DIR}/reports/${IMAGE_FILE}.tar"

IMAGE_TAR_SHA=$(sha256sum "${ARTIFACT_DIR}/reports/${IMAGE_FILE}.tar" | grep -E '^[a-zA-Z0-9]+' -o)
export IMAGE_TAR_SHA
