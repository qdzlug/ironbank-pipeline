#!/bin/bash
set -Eeuo pipefail

echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key
mkdir -p "${ARTIFACT_DIR}"

echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >staging_auth.json

skopeo copy --src-authfile staging_auth.json "docker://${STAGING_IMAGE_SHA}" "docker-archive:${ARTIFACT_DIR}/${IMAGE_FILE}.tar"
gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
echo "pinentry-mode loopback" >>"${HOME}"/.gnupg/gpg.conf
gpg --detach-sign -o "${IMAGE_FILE}.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" "${ARTIFACT_DIR}/${IMAGE_FILE}.tar"

# Stage image for upload
mv "${IMAGE_FILE}.sig" "${ARTIFACT_DIR}"
