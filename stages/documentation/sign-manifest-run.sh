#!/bin/bash
set -Eeuo pipefail
dnf install jq -y
podman load -i "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}"
echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key
mkdir -p "${ARTIFACT_DIR}"
GPG_VERSION=$(gpg --version | grep '(?<=gpg .GnuPG.)([^0-9]+)([0-9]+[.][0-9]+[.][0-9]+)' -oP | sed -E 's/ //g')
IMAGE_TAR_SHA=$(sha256sum "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" | grep -E '^[a-zA-Z0-9]+' -o)
IMAGE_PODMAN_SHA=$(podman inspect --format '{{.Digest}}' "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}")
# Create manifest.json

IMAGE_PODMAN_SHA="${IMAGE_PODMAN_SHA}" IMAGE_TAR_SHA="${IMAGE_TAR_SHA}" Path="${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}" GPG_VERSION="${GPG_VERSION}" jq -n -c '{"critical":{"type":"atomic container signature","image":{"podman-manifest-digest": env.IMAGE_PODMAN_SHA,"image-tar-sha256-checksum": env.IMAGE_TAR_SHA},"identity":{"podman-reference": env.Path }},"optional":{"creator": env.GPG_VERSION}}' >manifest.json
jq . manifest.json >manifest.tmp && mv manifest.tmp manifest.json
cat manifest.json
# Sign manifest.json
gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
echo "pinentry-mode loopback" >>"${HOME}"/.gnupg/gpg.conf
gpg --detach-sign -o "${SIG_FILE}.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" manifest.json
# Stage manifest for upload
mv manifest.json "${SIG_FILE}.sig" "${ARTIFACT_DIR}"
