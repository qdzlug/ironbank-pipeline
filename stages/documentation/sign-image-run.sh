#!/bin/bash
set -Eeuo pipefail

echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key
mkdir -p "${ARTIFACT_DIR}"

gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
echo "pinentry-mode loopback" >>"${HOME}"/.gnupg/gpg.conf
gpg --detach-sign -o "${IMAGE_FILE}.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar"

# Stage image for upload
mv "${IMAGE_FILE}.sig" "${ARTIFACT_DIR}"

mv "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${ARTIFACT_DIR}/${IMAGE_FILE}-${IMAGE_VERSION}.tar"
