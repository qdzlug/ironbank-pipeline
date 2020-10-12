#!/bin/bash
set -Eeuo pipefail
podman load -i "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}"
echo "${IB_CONTAINER_GPG_KEY}" | base64 -d > key
mkdir -m 0600 -p tmp_gpg "${ARTIFACT_DIR}"
gpg --homedir ./tmp_gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
echo "pinentry-mode loopback" >> ./tmp_gpg/gpg.conf
gpg --detach-sign --homedir ./tmp_gpg -o "${IMAGE_FILE}.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar"
# Stage image for upload
mv "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${IMAGE_FILE}.sig" "${ARTIFACT_DIR}"
