#!/bin/bash
set -Eeuo pipefail

echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >staging_auth.json

echo "Creating tarball"
skopeo copy --src-authfile staging_auth.json "docker://${REGISTRY_URL_STAGING}/${IMAGE_NAME}@${IMAGE_PODMAN_SHA}" "docker-archive:${IMAGE_FILE}.tar"
