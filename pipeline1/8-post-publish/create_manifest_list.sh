#!/bin/bash

# Creating a manifest list for each tag specified in the hardening_manifest.
# The images created by this pipeline are added to the manifest list and then the manifest list is pushed to harbor.
IFS=','
read -ra tags_array <<<"$TAGS_ARM64"
for tag in "${tags_array[@]}"; do
  echo "Creating manifest list for $REGISTRY_PUBLISH_URL/$IMAGE_NAME_ARM64:$tag"
  podman manifest create $REGISTRY_PUBLISH_URL/$IMAGE_NAME_ARM64:$tag
  podman manifest add $REGISTRY_PUBLISH_URL/$IMAGE_NAME_ARM64:$tag docker://$REGISTRY_PUBLISH_URL/$IMAGE_NAME_ARM64@$DIGEST_TO_SCAN_X86 --authfile $DOCKER_AUTH_FILE_PULL
  podman manifest add $REGISTRY_PUBLISH_URL/$IMAGE_NAME_ARM64:$tag docker://$REGISTRY_PUBLISH_URL/$IMAGE_NAME_ARM64@$DIGEST_TO_SCAN_ARM64 --authfile $DOCKER_AUTH_FILE_PULL
  podman manifest push --all $REGISTRY_PUBLISH_URL/$IMAGE_NAME_ARM64:$tag --authfile $DOCKER_AUTH_FILE_PUBLISH
done
