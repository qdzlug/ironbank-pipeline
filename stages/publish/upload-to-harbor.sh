#!/bin/bash
set -Eeuo pipefail

if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project' && [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects unless DOCKER_AUTH_CONFIG_TEST is set..."
  exit 1
fi

echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >>staging_auth.json

gun="${REGISTRY_URL}/${IM_NAME}"

# Perform vault login
vault login -method=userpass username="${NOTARY_STAGING_USERNAME}" password="${NOTARY_STAGING_PASSWORD}"
vault kv get -field=delegation.key kv/il2/notary/delegation1 | base64 -d >delegation.key

echo "Are we actually pulling the delegation key?"
cat delegation.key
echo "Did it cat out?"

notary -d trust-dir-delegate/ key import delegation.key

if [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "${DOCKER_AUTH_CONFIG_PROD}" | base64 -d >dest_auth.json
else
  echo "${DOCKER_AUTH_CONFIG_TEST}" | base64 -d >dest_auth.json
fi

# Copy from staging to prod with each tag listed in descriptions.yaml
while IFS= read -r tag; do
  # Sign the image with the delegation key
  notary -v -s "${NOTARY_STAGING_ADDR}" -d trust-dir-delegate add -p --roles=targets/releases "$gun" "${tag}" "${tag}_manifest.json"

  skopeo copy --src-authfile staging_auth.json --dest-authfile dest_auth.json \
    "docker://${STAGING_REGISTRY_URL}/${IM_NAME}@${IMAGE_PODMAN_SHA}" \
    "docker://${REGISTRY_URL}/${IM_NAME}:${tag}"

done <"${ARTIFACT_STORAGE}/preflight/tags.txt"
