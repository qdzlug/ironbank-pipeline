#!/bin/bash
set -Eeuo pipefail
shopt -s nullglob # Allow images/* and external-resources/* to match nothing

# TODO: remove IM_NAME eventually
export IM_NAME="$IMAGE_NAME"

mkdir -p "${ARTIFACT_DIR}"

# Determine source registry based on branch
if [ -n "${STAGING_BASE_IMAGE}" ]; then
  BASE_REGISTRY="${BASE_REGISTRY}-staging"
  DOCKER_AUTH_CONFIG_PULL="${DOCKER_AUTH_CONFIG_STAGING}"
fi

# Load any images used in Dockerfile build
for file in "${ARTIFACT_STORAGE}"/import-artifacts/images/*; do
  echo "loading image $file"
  podman load -i "$file" --storage-driver=vfs
done

# Load HTTP and S3 external resources
for file in "${ARTIFACT_STORAGE}"/import-artifacts/external-resources/*; do
  cp -v "$file" .
done

shopt -u nullglob # Disallow images/* and external-resources/* to match nothing

echo "${SATELLITE_URL} satellite" >>/etc/hosts
echo "${DOCKER_AUTH_CONFIG_PULL}" | base64 -d >>/tmp/prod_auth.json
echo "IM_NAME=${IM_NAME}" >>build.env
echo "/tmp/prod_auth.json" >>.dockerignore

# Convert env files to command line arguments
# Newlines are not allowed in the key or value
label_parameters=$(while IFS= read -r line; do
  echo "--label=$line"
done <"${ARTIFACT_STORAGE}/preflight/labels.env")
args_parameters=$(while IFS= read -r line; do
  echo "--build-arg=$line"
done <"${ARTIFACT_STORAGE}/preflight/args.env")

old_ifs=$IFS
IFS=$'\n'
# Intentional wordsplitting:
# shellcheck disable=SC2086
buildah bud \
  $args_parameters \
  --build-arg=BASE_REGISTRY="${BASE_REGISTRY}" \
  $label_parameters \
  --label=maintainer="ironbank@dsop.io" \
  --label=org.opencontainers.image.created="$(date --rfc-3339=seconds)" \
  --label=org.opencontainers.image.source="${CI_PROJECT_URL}" \
  --label=org.opencontainers.image.revision="${CI_COMMIT_SHA}" \
  --authfile /tmp/prod_auth.json \
  --format=docker \
  --loglevel=3 \
  --storage-driver=vfs \
  -t "${STAGING_REGISTRY_URL}/$IM_NAME" \
  .
IFS=$old_ifs

buildah tag --storage-driver=vfs "${STAGING_REGISTRY_URL}/$IM_NAME" "${STAGING_REGISTRY_URL}/$IM_NAME:${CI_PIPELINE_ID}"
echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >>staging_auth.json
buildah push --storage-driver=vfs --authfile staging_auth.json "${STAGING_REGISTRY_URL}/$IM_NAME:${CI_PIPELINE_ID}"

while IFS= read -r tag; do
  buildah push --storage-driver=vfs --authfile staging_auth.json "${STAGING_REGISTRY_URL}/$IM_NAME:${tag}"
done <"${ARTIFACT_DIR}/preflight/tags.txt"

# Provide tar for use in later stages, matching existing tar naming convention
skopeo copy --src-authfile staging_auth.json "docker://${STAGING_REGISTRY_URL}/$IM_NAME:${CI_PIPELINE_ID}" "docker-archive:${ARTIFACT_DIR}/${IMAGE_FILE}.tar"
echo "IMAGE_ID=sha256:$(podman inspect --storage-driver=vfs "${STAGING_REGISTRY_URL}/$IM_NAME" --format '{{.Id}}')" >>build.env
echo "IMAGE_TAR_SHA=$(sha256sum "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" | grep -E '^[a-zA-Z0-9]+' -o)" >>build.env
echo "IMAGE_PODMAN_SHA=$(podman inspect --format '{{.Digest}}' "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMAGE_VERSION}")" >>build.env
echo "IMAGE_FILE=${IMAGE_FILE}" >>build.env

