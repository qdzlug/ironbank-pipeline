#!/bin/bash
set -Eeuo pipefail
podman load -i "${ARTIFACT_STORAGE}/build/mongo-test-4.2.9.tar" "${STAGING_REGISTRY_URL}/opensource/pipeline-test-project/mongo-test:${IMG_VERSION}"
echo "${IB_CONTAINER_GPG_KEY}" | base64 -d > key
mkdir -m 0600 tmp_gpg
mkdir -p "${ARTIFACT_DIR}"
GPG_VERSION=$(gpg --version | grep '(?<=gpg .GnuPG.)([^0-9]+)([0-9]+[.][0-9]+[.][0-9]+)' -oP | sed -E 's/ //g')
IMAGE_TAR_SHA=$(sha256sum "${ARTIFACT_STORAGE}/build/mongo-test-4.2.9.tar" | grep -E '^[a-zA-Z0-9]+' -o)
IMAGE_PODMAN_SHA=$(podman inspect --format '{{.Digest}}' "${STAGING_REGISTRY_URL}/opensource/pipeline-test-project/mongo-test:${IMG_VERSION}")
# Create manifest.json

cat <<EOF > manifest.json
{
    "critical": {
            "type": "atomic container signature",
            "image": {
            "podman-manifest-digest": "${IMAGE_PODMAN_SHA}",
            "image-tar-sha256-checksum": "${IMAGE_TAR_SHA}"
        },
    "identity": {
        "podman-reference": "${STAGING_REGISTRY_URL}/opensource/pipeline-test-project/mongo-test:${IMG_VERSION}"
        }
},
"optional": {
    "creator": "${GPG_VERSION}"
}
}
EOF
cat manifest.json
# Clear
rm -rf tmp_gpg/*
# Sign manifest.json
gpg --homedir ./tmp_gpg --import --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" key
ls -al ./tmp_gpg
echo "pinentry-mode loopback" >> ./tmp_gpg/gpg.conf
gpg --detach-sign --homedir ./tmp_gpg -o "${SIG_FILE}.sig" --armor --yes --batch --passphrase "${IB_CONTAINER_SIG_KEY_PASSPHRASE}" manifest.json
# Stage manifest for upload
mv manifest.json "${SIG_FILE}.sig" "${ARTIFACT_DIR}"
