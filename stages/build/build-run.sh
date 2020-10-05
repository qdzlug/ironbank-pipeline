#!/bin/bash
set -Eeuo pipefail
shopt -s nullglob # Allow images/* and external-resources/* to match nothing

IM_NAME=$(echo "${CI_PROJECT_PATH}" | sed -e 's/.*dsop\/\(.*\)/\1/')
export IM_NAME

mkdir -p "${ARTIFACT_DIR}"

# Determine source registry based on branch
if [ "${CI_COMMIT_BRANCH}" != "master"  ]; then
  BASE_REGISTRY="${BASE_REGISTRY}-staging"
  DOCKER_AUTH_CONFIG_PULL="${DOCKER_AUTH_CONFIG_STAGING}"
fi

# Load any images used in Dockerfile build
for file in ${ARTIFACT_STORAGE}/import-artifacts/images/*; do
  echo "loading image $file"
  podman load -i "$file" --storage-driver=vfs
done

# Load HTTP and S3 external resources
for file in "${ARTIFACT_STORAGE}"/import-artifacts/external-resources/*; do
    cp -v "$file" .
done

echo "${BASE_REGISTRY} ${BASE_IMAGE} ${BASE_TAG}"
echo "${SATELLITE_URL} satellite" >> /etc/hosts
echo "${DOCKER_AUTH_CONFIG_PULL}" | base64 -d >> /tmp/prod_auth.json
echo "IM_NAME=${IM_NAME}" >> build.env
echo "/tmp/prod_auth.json" >> .dockerignore
# Set the tag to eliminate /build/dsop and matching existing project hierarchy format
HARBOR_IMAGE_PATH="${STAGING_REGISTRY_URL}/$IM_NAME:$IMG_VERSION"
buildah bud \
    --build-arg "BASE_REGISTRY=${BASE_REGISTRY}" \
    --build-arg "BASE_IMAGE=${BASE_IMAGE:-}" \
    --build-arg "BASE_TAG=${BASE_TAG:-}" \
    --authfile /tmp/prod_auth.json \
    --format=docker \
    --storage-driver=vfs \
    -t "${HARBOR_IMAGE_PATH}" \
    .
buildah tag --storage-driver=vfs "${HARBOR_IMAGE_PATH}"  "${HARBOR_IMAGE_PATH}-${CI_PIPELINE_ID}"
echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >> staging_auth.json
buildah push --storage-driver=vfs --authfile staging_auth.json "${HARBOR_IMAGE_PATH}-${CI_PIPELINE_ID}"
buildah push --storage-driver=vfs --authfile staging_auth.json "${HARBOR_IMAGE_PATH}"
# Provide tar for use in later stages, matching existing tar naming convention
skopeo copy --src-authfile staging_auth.json "docker://${HARBOR_IMAGE_PATH}-${CI_PIPELINE_ID}" "docker-archive:${ARTIFACT_DIR}/${IMAGE_FILE}.tar"
echo "IMAGE_ID=sha256:$(podman inspect --storage-driver=vfs "${HARBOR_IMAGE_PATH}" --format '{{.Id}}')" >> build.env
