#!/bin/bash
set -Eeuo pipefail

mkdir -p "${ARTIFACT_DIR}/reports"

skopeo copy --src-authfile staging_auth.json "docker://${STAGING_REGISTRY_URL}/${IMAGE_NAME}@${IMAGE_PODMAN_SHA}" "docker-archive:${ARTIFACT_DIR}/reports/${IMAGE_FILE}.tar"
