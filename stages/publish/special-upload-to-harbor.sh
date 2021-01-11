#!/bin/bash
set -Eeuo pipefail
if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project'; then
  echo "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects..."
  exit 0
fi
echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >>staging_auth.json
echo "${DOCKER_AUTH_CONFIG_PROD}" | base64 -d >>prod_auth.json

# Upload image to prod Harbor for special images
while IFS= read -r tag; do
  skopeo copy --src-authfile staging_auth.json --dest-authfile prod_auth.json \
    "docker://${STAGING_REGISTRY_URL}/${IM_NAME}:@${IMAGE_PODMAN_SHA}" \
    "docker://${REGISTRY_URL}/${SPECIAL_IMAGE_PATH}:${tag}"
done <"${ARTIFACT_DIR}/preflight/tags.txt"
