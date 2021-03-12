#!/bin/bash
set -Eeuo pipefail

if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project' && [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects unless DOCKER_AUTH_CONFIG_TEST is set..."
  exit 1
fi

echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >>staging_auth.json

staging_image="${STAGING_REGISTRY_URL}/${IM_NAME}"
gun="${REGISTRY_URL}/${IM_NAME}"

# Grab the delegation key from vault
vault login -no-print=true -method=userpass username="${VAULT_STAGING_USERNAME}" password="${VAULT_STAGING_PASSWORD}"
# TODO Make dynamic based off naming scheme
vault kv get -field=delegation.key kv/il2/notary/delegation1 >delegation.key

# Import the delegation key to notary
notary -d trust-dir-delegate/ key import delegation.key
rm delegation.key

if [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "${DOCKER_AUTH_CONFIG_PROD}" | base64 -d >dest_auth.json
else
  echo "${DOCKER_AUTH_CONFIG_TEST}" | base64 -d >dest_auth.json
fi

# Copy from staging to prod with each tag listed in descriptions.yaml
echo "Read the tags"
tags_file="${ARTIFACT_STORAGE}/preflight/tags.txt"
test -f "$tags_file"


while IFS= read -r tag; do

  echo "Pulling ${tag}_manifest.json"
  skopeo inspect --authfile staging_auth.json --raw "docker://${staging_image}:${tag}" >"${tag}_manifest.json"

  cat "${tag}_manifest.json"

  # Sign the image with the delegation key
  echo "Signing with notary"
  notary -v -s "${NOTARY_URL}" -d trust-dir-delegate add -p --roles=targets/releases "$gun" "${tag}" "${tag}_manifest.json"

  echo "Copy from staging to destination"
  skopeo copy --src-authfile staging_auth.json --dest-authfile dest_auth.json \
    "docker://${staging_image}@${IMAGE_PODMAN_SHA}" \
    "docker://${REGISTRY_URL}/${IM_NAME}:${tag}"

  echo "======"

done <"${tags_file}"
