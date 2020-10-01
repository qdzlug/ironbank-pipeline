#!/bin/bash
set -Eeuo pipefail
IM_NAME=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')
export IM_NAME
mkdir -p "${ARTIFACT_DIR}"
# Load any images used in Dockerfile build
if [ -d "${ARTIFACT_STORAGE}/import-artifacts/images" ]; then
  for file in ${ARTIFACT_STORAGE}/import-artifacts/images/*; do
    echo "loading image $file"
    podman load -i $file --storage-driver=vfs
  done
fi
if [ -d "${ARTIFACT_STORAGE}/import-artifacts/external-resources/" ]; then
    cp -r -v "${ARTIFACT_STORAGE}/import-artifacts/external-resources/*" .
fi

echo "${SATELLITE_URL} satellite" >> /etc/hosts
echo "${DOCKER_AUTH_CONFIG_PULL}" | base64 -d >> prod_auth.json
echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >> staging_auth.json
echo "IM_NAME=${IM_NAME}" >> build.env
# Set the tag to eliminate /build/dsop and matching existing project hierarchy format
HARBOR_IMAGE_PATH="${STAGING_REGISTRY_URL}/$IM_NAME:$IMG_VERSION"
buildah bud \
    --build-arg "BASE_REGISTRY=${REGISTRY_URL}" \
    --build-arg "BASE_IMAGE=${BASE_IMAGE:-}" \
    --build-arg "BASE_TAG=${BASE_TAG:-}" \
    --authfile prod_auth.json \
    --format=docker \
    --storage-driver=vfs \
    -t "${HARBOR_IMAGE_PATH}" \
    .
buildah tag --storage-driver=vfs "${HARBOR_IMAGE_PATH}"  "${HARBOR_IMAGE_PATH}-${CI_PIPELINE_ID}"
buildah push --storage-driver=vfs --authfile staging_auth.json "${HARBOR_IMAGE_PATH}-${CI_PIPELINE_ID}"
# Provide tar for use in later stages, matching existing tar naming convention
skopeo copy --src-authfile staging_auth.json "docker://${HARBOR_IMAGE_PATH}-${CI_PIPELINE_ID}" "docker-archive:${ARTIFACT_DIR}/${IMAGE_FILE}.tar"
echo "IMAGE_ID=sha256:$(podman inspect --storage-driver=vfs "${HARBOR_IMAGE_PATH}" --format {{'.Id'}})" >> build.env
