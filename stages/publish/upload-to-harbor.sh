#!/bin/bash
set -Exeuo pipefail
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

# Import the delegation key
notary -d trust-dir-delegate/ key import delegation.key

# Load image from tarball
podman load -i "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "currentimage" --storage-driver=vfs

push_and_sign() {

    current_tag=${1}

    podman tag "currentimage" "$gun:$current_tag" --storage-driver=vfs

    # Upload image to prod Harbor
    podman push --authfile prod_auth.json \
      "docker://$gun:$current_tag" \
      --storage-driver=vfs \
      --digestfile "${current_tag}_digest"

    # Can we remove the skopeo dependency here? podman inspect doesn't output --raw and therefore might mess with the manifest.json sha
    skopeo inspect --authfile prod_auth.json --raw "docker://${gun}:${current_tag}" >"${current_tag}_manifest.json"

    # There's a chance for a TOCTOU attack/bug here. Make sure the digest matches this file:
    echo "$(cut -d: -f2 "${current_tag}_digest") ${current_tag}_manifest.json" | sha256sum --check

    # Sign the image with the delegation key
    notary -v -s "${NOTARY_URL}" -d trust-dir-delegate add -p --roles=targets/releases "$gun" "$current_tag" "${current_tag}_manifest.json"
}

push_and_sign "$tag"
push_and_sign latest
