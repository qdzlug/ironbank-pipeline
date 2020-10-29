#!/bin/bash
set -Eeuo pipefail

# Removed for testing
#if [[ $(echo "${CI_PROJECT_DIR}" | grep -e 'pipeline-test-project') ]]; then
#  echo "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects..."
#  exit 0
#fi

if [ -z "${1}" ] || [ -z "${2}" ]; then
  echo '$gun or $tag not provided as arguments, exiting'
  exit 1
fi

gun="${1}"
tag="${2}"
# Changed for testing
echo "${DOCKER_AUTH_CONFIG_TEST}" | base64 -d >prod_auth.json
echo "${NOTARY_DELEGATION_KEY}" | base64 -d >delegation.key

# Load image from tarball
podman load -i "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "$gun:$tag" --storage-driver=vfs
podman tag "$gun:$tag" "$gun:latest" --storage-driver=vfs

# Upload image to prod Harbor
podman push --dest-authfile prod_auth.json \
  "docker://$gun:$tag" \
  --storage-driver=vfs
# Copy from staging to prod with latest tag
podman push --dest-authfile prod_auth.json \
  "docker://$gun:latest" \
  --storage-driver=vfs

# Capture image digest for the image we just published
image_version_digest=$(podman inspect "$gun:$tag" | jq --arg gun "$gun" -r '(.[0].RepoDigests | map(select(startswith($gun + "@sha256"))))[0] | split(":")[1]')

# Can we remove the skopeo dpendency here? podman inspect doesn't output --raw and therefore might mess with the manifest.json sha
skopeo inspect --raw "docker://${gun}:${tag}" >manifest.json

# There's a chance for a TOCTOU attack/bug here. Make sure the digest matches this file:
echo "${image_version_digest} manifest.json" | sha256sum --check

# Import the delegation key
notary -d trust-dir-delegate/ key import delegation.key

# Sign the image with the delegation key
notary -v -s "${NOTARY_URL}" -d trust-dir-delegate add -p --roles=targets/releases "$gun" "$tag" "manifest.json"
notary -v -s "${NOTARY_URL}" -d trust-dir-delegate add -p --roles=targets/releases "$gun" latest "manifest.json"
