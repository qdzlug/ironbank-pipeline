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
done <"${ARTIFACT_STORAGE}/lint/labels.env")

echo "Converting build args from hardening manifest into command line args"
args_parameters=$(while IFS= read -r line; do
  echo "--build-arg=$line"
done <"${ARTIFACT_STORAGE}/lint/args.env")

# Start up the forward proxy
echo "Start up the forward proxy"
squid -k parse -f "${PIPELINE_REPO_DIR}"/stages/build/squid.conf
squid -f "${PIPELINE_REPO_DIR}"/stages/build/squid.conf
sleep 5 # because squid will not start properly without this

echo "Adding the ironbank.repo to the container via mount.conf"
# Must be able to overrride DISTRO_REPO_DIR to equal '' and cannot simply check for vars existence
# shellcheck disable=SC2236
if [ ! -z "${DISTRO_REPO_DIR:-}" ]; then
  echo "${PWD}/${PIPELINE_REPO_DIR}/stages/build/${DISTRO_REPO_DIR}:${DISTRO_REPO_MOUNT}" >>"${HOME}"/.config/containers/mounts.conf
fi

# add override to gemrc for ruby gem support
echo "${PWD}/${PIPELINE_REPO_DIR}/stages/build/ruby/.ironbank-gemrc:/tmp/ruby/.ironbank-gemrc" >>"${HOME}"/.config/containers/mounts.conf

# Set up ARG(s) in Dockerfile to recieve the buildah bud --build-arg so that the container owner won't have to deal with it.
# These will not persist and will only be available to the build process.
# buildah bud ignores this requirement for http/ftp/no proxy envvars, but we're required to do this for anything else.
cp "${PIPELINE_REPO_DIR}"/stages/build/build-args.txt .
sed -i '/^FROM /r build-args.txt' Dockerfile

old_ifs=$IFS
IFS=$'\n'
echo "Build the image"
PARENT_LABEL=""
# shellcheck disable=SC2236
if [ ! -z "${BASE_IMAGE:-}" ]; then
  # shellcheck disable=SC2086
  BASE_SHA=$(grep -Po '(?<="BASE_SHA": ")[^"]*' ${ARTIFACT_STORAGE}/lint/base_image.json)
  PARENT_LABEL="registry1.dso.mil/${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG}@${BASE_SHA}"
fi
# Intentional wordsplitting:
# shellcheck disable=SC2086
env -i BUILDAH_ISOLATION=chroot PATH="$PATH" buildah bud \
  $args_parameters \
  --build-arg=BASE_REGISTRY="${BASE_REGISTRY}" \
  --build-arg=http_proxy="http://localhost:3128" \
  --build-arg=HTTP_PROXY="http://localhost:3128" \
  --build-arg=GOPROXY="http://nexus-repository-manager.nexus-repository-manager.svc.cluster.local:8081/repository/goproxy/" \
  --build-arg=GOSUMDB="sum.golang.org http://nexus-repository-manager.nexus-repository-manager.svc.cluster.local:8081/repository/gosum" \
  --build-arg=PIP_INDEX_URL="http://nexus-repository-manager.nexus-repository-manager.svc.cluster.local:8081/repository/pypi/simple/" \
  --build-arg=PIP_TRUSTED_HOST="nexus-repository-manager.nexus-repository-manager.svc.cluster.local" \
  --build-arg=NPM_CONFIG_REGISTRY="http://nexus-repository-manager.nexus-repository-manager.svc.cluster.local:8081/repository/npmproxy/" \
  --build-arg=GEMRC="/tmp/ruby/.ironbank-gemrc" \
  $label_parameters \
  --label=maintainer="ironbank@dsop.io" \
  --label=org.opencontainers.image.created="$(date --rfc-3339=seconds)" \
  --label=org.opencontainers.image.source="${CI_PROJECT_URL}" \
  --label=org.opencontainers.image.revision="${CI_COMMIT_SHA}" \
  --label=mil.dso.ironbank.image.parent="${PARENT_LABEL}" \
  --authfile /tmp/prod_auth.json \
  --format=oci \
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
  tags_file="${ARTIFACT_STORAGE}/lint/tags.txt"
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
