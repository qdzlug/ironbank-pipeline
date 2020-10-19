#!/bin/bash
set -Eeuo pipefail
if [[ $(echo "${CI_PROJECT_DIR}" | grep -e 'pipeline-test-project') ]]; then
  echo "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects..."
  exit 0
fi
echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >staging_auth.json
echo "${DOCKER_AUTH_CONFIG_PROD}" | base64 -d >prod_auth.json

# Upload image to prod Harbor
skopeo copy --src-authfile staging_auth.json --dest-authfile prod_auth.json \
  "docker://${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}-${CI_PIPELINE_ID}" \
  "docker://${REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}"
# Copy from staging to prod with latest tag
skopeo copy --src-authfile staging_auth.json --dest-authfile prod_auth.json \
  "docker://${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}-${CI_PIPELINE_ID}" \
  "docker://${REGISTRY_URL}/${IM_NAME}:latest"