#!/bin/bash
set -Eeuo pipefail

echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key
mkdir -p "${ARTIFACT_DIR}"

mv "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${ARTIFACT_DIR}/${CI_PROJECT_NAME}-${IMAGE_VERSION}.tar"

gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
echo "pinentry-mode loopback" >>"${HOME}"/.gnupg/gpg.conf
gpg --detach-sign -o "${CI_PROJECT_NAME}-${IMAGE_VERSION}.tar.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" "${ARTIFACT_DIR}/${CI_PROJECT_NAME}-${IMAGE_VERSION}.tar"

# Stage image for upload
mv "${CI_PROJECT_NAME}-${IMAGE_VERSION}.tar.sig" "${ARTIFACT_DIR}"
