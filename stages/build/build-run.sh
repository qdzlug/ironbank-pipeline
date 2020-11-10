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

echo "${SATELLITE_URL} satellite" >>/etc/hosts
echo "${DOCKER_AUTH_CONFIG_PULL}" | base64 -d >>/tmp/prod_auth.json
echo "IM_NAME=${IM_NAME}" >>build.env
echo "/tmp/prod_auth.json" >>.dockerignore

# Convert env files to command line arguments
# values are already escaped with shlex
label_parameters=$(while IFS= read -r line; do
    echo "--label=$line"
done < "${ARTIFACT_STORAGE}/preflight/labels.env")
args_parameters=$(while IFS= read -r line; do
    echo "--build-arg=$line"
done < "${ARTIFACT_STORAGE}/preflight/args.env")

set -x
buildah bud \
  --build-arg "BASE_REGISTRY=${BASE_REGISTRY}" \
  $label_parameters \
  $args_parameters \
  --label dccscr.git.commit.id="${CI_COMMIT_SHA}" \
  --label dccscr.git.commit.url="${CI_PROJECT_URL}/tree/${CI_COMMIT_SHA}" \
  --label dccscr.git.url="${CI_PROJECT_URL}.git" \
  --label dccscr.git.branch="${CI_COMMIT_BRANCH}" \
  --label dccscr.image.build.date="$(date --utc)" \
  --label dccscr.image.build.id="${CI_PIPELINE_ID}" \
  --label dccscr.image.name="${CI_PROJECT_NAME}" \
  --label dccscr.ironbank.approval.status="${IMAGE_APPROVAL_STATUS}" \
  --label dccscr.ironbank.approval.url="TBD" \
  --label dccscr.ironbank.url="TBD" \
  --label dcar_status="${IMAGE_APPROVAL_STATUS}" \
  --authfile /tmp/prod_auth.json \
  --format=docker \
  --loglevel=3 \
  --storage-driver=vfs \
  -t "${STAGING_REGISTRY_URL}/$IM_NAME" \
  .
set +x

buildah tag --storage-driver=vfs "${STAGING_REGISTRY_URL}/$IM_NAME" "${STAGING_REGISTRY_URL}/$IM_NAME:${CI_PIPELINE_ID}"
echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >>staging_auth.json
buildah push --storage-driver=vfs --authfile staging_auth.json "${STAGING_REGISTRY_URL}/$IM_NAME:${CI_PIPELINE_ID}"

while IFS= read -r tag; do
    buildah push --storage-driver=vfs --authfile staging_auth.json "${STAGING_REGISTRY_URL}/$IM_NAME:${tag}"
done < "${ARTIFACT_DIR}/preflight/tags.txt"

# Provide tar for use in later stages, matching existing tar naming convention
skopeo copy --src-authfile staging_auth.json "docker://${STAGING_REGISTRY_URL}/$IM_NAME:${CI_PIPELINE_ID}" "docker-archive:${ARTIFACT_DIR}/${IMAGE_FILE}.tar"
echo "IMAGE_ID=sha256:$(podman inspect --storage-driver=vfs "${STAGING_REGISTRY_URL}/$IM_NAME" --format '{{.Id}}')" >>build.env
