#!/bin/env bash

set -Eeuo pipefail

#
# ARTIFACT_DIR     = the directory for artifacts in this current stage
# ARTIFACT_STORAGE - the base artifact directory used to access artifacts from other stages
#

# Set up the image reference variables
export IMAGE_REGISTRY_REPO="${STAGING_REGISTRY_URL}/${IMAGE_NAME}"
export IMAGE_FULLTAG="${IMAGE_REGISTRY_REPO}:ibci-${CI_PIPELINE_ID}"

mkdir -p "${ARTIFACT_DIR}"

shopt -s nullglob # Allow images/* and external-resources/* to match nothing

echo "Determine source registry based on branch"
# Determine source registry based on branch
if [ -n "${STAGING_BASE_IMAGE}" ]; then
  BASE_REGISTRY="${BASE_REGISTRY}-staging"
  DOCKER_AUTH_CONFIG_PULL="${DOCKER_AUTH_CONFIG_STAGING}"
fi

echo "Load any images used in Dockerfile build"
# Load any images used in Dockerfile build
for file in "${ARTIFACT_STORAGE}"/import-artifacts/images/*; do
  echo "loading image $file"
  podman load -i "$file" --storage-driver=vfs
done

echo "Load HTTP and S3 external resources"
# Load HTTP and S3 external resources
for file in "${ARTIFACT_STORAGE}"/import-artifacts/external-resources/*; do
  cp -v "$file" .
done

shopt -u nullglob # Disallow images/* and external-resources/* to match nothing

echo "${DOCKER_AUTH_CONFIG_PULL}" | base64 -d >>/tmp/prod_auth.json
echo "/tmp/prod_auth.json" >>.dockerignore

# Convert env files to command line arguments
# Newlines are not allowed in the key or value
echo "Converting labels from hardening manifest into command line args"
label_parameters=$(while IFS= read -r line; do
  echo "--label=$line"
done <"${ARTIFACT_STORAGE}/preflight/labels.env")

echo "Converting build args from hardening manifest into command line args"
args_parameters=$(while IFS= read -r line; do
  echo "--build-arg=$line"
done <"${ARTIFACT_STORAGE}/preflight/args.env")

# Start up the forward proxy
echo "Start up the forward proxy"
squid -k parse -f /tmp/squid.conf
squid -f /tmp/squid.conf
sleep 5 # because squid will not start properly without this

echo "Adding the ironbank.repo to the containter via mount.conf"
# Must be able to overrride DISTRO_REPO_DIR to equal '' and cannot simply check for vars existence
# shellcheck disable=SC2236
if [ ! -z "${DISTRO_REPO_DIR:-}" ]; then
  echo "${PWD}/${PIPELINE_REPO_DIR}/stages/build/${DISTRO_REPO_DIR}:${DISTRO_REPO_MOUNT}" >>"${HOME}"/.config/containers/mounts.conf
fi

old_ifs=$IFS
IFS=$'\n'
echo "Build the image"
# Intentional wordsplitting:
# shellcheck disable=SC2086
env -i BUILDAH_ISOLATION=chroot PATH="$PATH" buildah bud \
  $args_parameters \
  --build-arg=BASE_REGISTRY="${BASE_REGISTRY}" \
  --build-arg=GOPROXY="http://nexus-repository-manager.nexus-repository-manager.svc.cluster.local:8081/repository/goproxy/" \
  --build-arg=GOSUMDB="sum.golang.org http://nexus-repository-manager.nexus-repository-manager.svc.cluster.local:8081/repository/gosum" \
  $label_parameters \
  --label=maintainer="ironbank@dsop.io" \
  --label=org.opencontainers.image.created="$(date --rfc-3339=seconds)" \
  --label=org.opencontainers.image.source="${CI_PROJECT_URL}" \
  --label=org.opencontainers.image.revision="${CI_COMMIT_SHA}" \
  --authfile /tmp/prod_auth.json \
  --format=docker \
  --log-level=warn \
  --default-mounts-file="${HOME}"/.config/containers/mounts.conf \
  --storage-driver=vfs \
  -t "${IMAGE_REGISTRY_REPO}" \
  .
IFS=$old_ifs

echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >>staging_auth.json

set -x

buildah tag --storage-driver=vfs "${IMAGE_REGISTRY_REPO}" "${IMAGE_FULLTAG}"

buildah push --storage-driver=vfs --authfile staging_auth.json --digestfile="${ARTIFACT_DIR}/digest" "${IMAGE_FULLTAG}"

function push_tags() {
  echo "Read the tags"
  tags_file="${ARTIFACT_STORAGE}/preflight/tags.txt"
  test -f "$tags_file"
  while IFS= read -r tag; do
    buildah tag --storage-driver=vfs "${IMAGE_REGISTRY_REPO}" "${IMAGE_REGISTRY_REPO}:${tag}"
    buildah push --storage-driver=vfs --authfile staging_auth.json "${IMAGE_REGISTRY_REPO}:${tag}"
  done <"$tags_file"
}

if [[ -n "${STAGING_BASE_IMAGE}" || "${CI_COMMIT_BRANCH}" == "development" ]]; then
  push_tags
fi

IMAGE_ID=sha256:$(podman inspect --storage-driver=vfs "${IMAGE_REGISTRY_REPO}" --format '{{.Id}}')
{
  echo "IMAGE_ID=${IMAGE_ID}"

  IMAGE_PODMAN_SHA=$(<"${ARTIFACT_DIR}/digest")
  echo "IMAGE_PODMAN_SHA=${IMAGE_PODMAN_SHA}"

  echo "IMAGE_FULLTAG=${IMAGE_FULLTAG}"

  echo "IMAGE_NAME=${IMAGE_NAME}"
} >>build.env

echo "Archive the proxy access log"
chmod 644 access.log
cp access.log "${ARTIFACT_DIR}/access_log"
