#!/bin/bash
# Listing environment variables available to the job.
env

# Creating a manifest list for each tag specified in the hardening_manifest.
# The images created by this pipeline are added to the manifest list and then the manifest list is pushed to harbor.
IFS=','
read -ra tags_array <<< "$TAGS_ARM64"
for tag in "${tags_array[@]}"; do 
  echo "podman manifest create $REGISTRY_PUBLISH_URL_ARM64:$tag"
  podman manifest create $REGISTRY_PUBLISH_URL_ARM64:$tag

  echo "podman manifest add $REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64:$tag docker://$REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64@$DIGEST_TO_SCAN_X86"
  podman manifest add $REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64:$tag docker://$REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64@$DIGEST_TO_SCAN_X86

  echo "podman manifest add $REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64:$tag docker://$REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64@$DIGEST_TO_SCAN_ARM64"
  podman manifest add $REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64:$tag docker://$REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64@$DIGEST_TO_SCAN_ARM64

  echo "podman manifest push --all $REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64:$tag"
  podman manifest push --all $REGISTRY_PUBLISH_URL_ARM64/$IMAGE_NAME_ARM64:$tag
done