#!/bin/bash
set -Eeuo pipefail
podman load -i "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}"
echo "${IB_CONTAINER_GPG_KEY}" | base64 -d > key
mkdir -p "${ARTIFACT_DIR}"
gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
echo "pinentry-mode loopback" >> "${HOME}"/.gnupg/gpg.conf
gpg --detach-sign -o "${IMAGE_FILE}.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar"
# Stage image for upload
mv "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${IMAGE_FILE}.sig" "${ARTIFACT_DIR}"
