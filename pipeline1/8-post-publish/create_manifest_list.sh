#!/bin/bash
set -euo pipefail

TAGS=$(awk -F'=' '/^TAGS/ {print $2}' "$ARTIFACT_STORAGE/harbor"/*/upload_to_harbor.env | head -n 1)
IMAGE_NAME=$(awk -F'=' '/^IMAGE_NAME/ {print $2}' "$ARTIFACT_STORAGE/harbor"/*/upload_to_harbor.env | head -n 1)
IFS=','
read -ra TAGS_ARRAY <<<"$TAGS"
# loop over tags to create a manifest, add each image (arch), and push to harbor
for TAG in "${TAGS_ARRAY[@]}"; do
  echo "Creating manifest for $REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG"
  podman manifest create "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG"
  # add image digest per platform
  for HARBOR_DIR in "$ARTIFACT_STORAGE/harbor"/*; do
    PLATFORM=$(basename "$HARBOR_DIR")
    DIGEST_TO_SCAN=$(awk -F'=' '/^DIGEST_TO_SCAN/ {print $2}' "$ARTIFACT_STORAGE/harbor/$PLATFORM/upload_to_harbor.env")
    podman manifest add "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG" "docker://$REGISTRY_PUBLISH_URL/$IMAGE_NAME@$DIGEST_TO_SCAN" --authfile "$DOCKER_AUTH_FILE_PULL"
  done

  # push manifest
  podman manifest push --all "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG" --authfile "$DOCKER_AUTH_FILE_PUBLISH"

  # inspect an image for manifest list sha
  podman pull "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG" --authfile "$DOCKER_AUTH_FILE_PUBLISH"
  MANIFEST_LIST_SHA=$(podman image inspect --format='{{index .Digest}}' "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG")

  # sign
  mkdir -p "$HOME/.docker" && cp "$DOCKER_AUTH_FILE_PUBLISH" ~/.docker/config.json
  DOCKER_CONFIG="$HOME/.docker/config.json" cosign sign \
    --key="$KMS_KEY_SHORT_ARN" \
    --certificate="$COSIGN_CERT" \
    --tlog-upload=false \
    "$REGISTRY_PUBLISH_URL/$IMAGE_NAME@$MANIFEST_LIST_SHA"
done
