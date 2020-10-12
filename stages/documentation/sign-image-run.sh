#!/bin/bash
set -Eeuo pipefail
podman load -i "${ARTIFACT_STORAGE}/build/mongo-test-4.2.9.tar" "${STAGING_REGISTRY_URL}/opensource/pipeline-test-project/mongo-test:${IMG_VERSION}"
echo "${IB_CONTAINER_GPG_KEY}" | base64 -d > key
mkdir -m 0700 tmp_gpg
mkdir -p "${ARTIFACT_DIR}"
gpg --homedir ./tmp_gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
echo "pinentry-mode loopback" >> ./tmp_gpg/gpg.conf
gpg --detach-sign --homedir ./tmp_gpg -o "${IMAGE_FILE}.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" "${ARTIFACT_STORAGE}/build/mongo-test-4.2.9.tar"
# Stage image for upload
mv "${ARTIFACT_STORAGE}/build/mongo-test-4.2.9.tar" "${IMAGE_FILE}.sig" "${ARTIFACT_DIR}"
