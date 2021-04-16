#!/bin/bash
set -Eeuo pipefail

echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key
mkdir -p "${ARTIFACT_DIR}"

skopeo copy --src-authfile staging_auth.json "docker://${STAGING_REGISTRY_URL}/${IMAGE_NAME}@${IMAGE_PODMAN_SHA}" "docker-archive:${ARTIFACT_DIR}/${IMAGE_FILE}.tar"
gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
echo "pinentry-mode loopback" >>"${HOME}"/.gnupg/gpg.conf
gpg --detach-sign -o "${IMAGE_FILE}.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" "${ARTIFACT_DIR}/${IMAGE_FILE}.tar"

# Stage image for upload
mv "${IMAGE_FILE}.sig" "${ARTIFACT_DIR}"
