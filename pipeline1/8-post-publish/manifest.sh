#!/bin/bash
set -euo pipefail

# auth
mkdir -p "$HOME/.docker"
cp "$DOCKER_AUTH_FILE_PUBLISH" "$HOME/.docker/config.json"

# image
IMAGE_NAME=$(awk -F'=' '/^IMAGE_NAME/ {print $2}' "$ARTIFACT_STORAGE/harbor"/*/upload_to_harbor.env | head -n 1)

# tag csv
TAGS=$(awk -F'=' '/^TAGS/ {print $2}' "$ARTIFACT_STORAGE/harbor"/*/upload_to_harbor.env | head -n 1)
IFS=','
read -ra TAGS_ARRAY <<<"$TAGS"

# each tag becomes a manifest
for TAG in "${TAGS_ARRAY[@]}"; do

  echo "INFO creating manifest $REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG"
  podman manifest create "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG"

  # each arch is an image in the tag manifest
  for HARBOR_DIR in "$ARTIFACT_STORAGE/harbor"/*; do
    PLATFORM=$(basename "$HARBOR_DIR")
    DIGEST_TO_SCAN=$(awk -F'=' '/^DIGEST_TO_SCAN/ {print $2}' "$ARTIFACT_STORAGE/harbor/$PLATFORM/upload_to_harbor.env")
    echo "INFO adding $REGISTRY_PUBLISH_URL/$IMAGE_NAME@$DIGEST_TO_SCAN"
    podman manifest add "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG" "docker://$REGISTRY_PUBLISH_URL/$IMAGE_NAME@$DIGEST_TO_SCAN" --authfile "$DOCKER_AUTH_FILE_PULL"
  done

  # push manifest
  echo "INFO publishing $REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG"
  podman manifest push --all "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG" --authfile "$DOCKER_AUTH_FILE_PUBLISH"

  # inspect an image for manifest list sha
  podman pull "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG" --authfile "$DOCKER_AUTH_FILE_PUBLISH"
  MANIFEST_LIST_SHA=$(podman image inspect --format='{{index .Digest}}' "$REGISTRY_PUBLISH_URL/$IMAGE_NAME:$TAG")
  echo "INFO mainfest sha found, URI: $REGISTRY_PUBLISH_URL/$IMAGE_NAME@$MANIFEST_LIST_SHA"
done

# clean existing attestations (because we're not passing --replace as there may be more than one of the same)
echo "INFO cleaning attestations"
DOCKER_CONFIG="$HOME/.docker" cosign clean \
  --type attestation \
  --force \
  "$REGISTRY_PUBLISH_URL/$IMAGE_NAME@$MANIFEST_LIST_SHA"

# each arch adds attestations
for SBOM_DIR in "$ARTIFACT_STORAGE/sbom"/*; do

  # amd64, arm64
  PLATFORM=$(basename "$SBOM_DIR")

  # various paths of artifacts that become attestations
  for ARTIFACT_FILE in \
    "$ARTIFACT_STORAGE/sbom/$PLATFORM"/* \
    "$ARTIFACT_STORAGE/harbor/$PLATFORM/vat_response_lineage.json" \
    "$HOME/hardening_manifest.json" \
  ; do
    case $(basename "$ARTIFACT_FILE") in
      "sbom-cyclonedx-json.json")
        PREDICATE_TYPE="cyclonedx.org/bom"
        ;;
      "sbom-spdx-json.json")
        PREDICATE_TYPE="https://spdx.dev/Document"
        ;;
      "sbom-syft-json.json")
        PREDICATE_TYPE="https://github.com/anchore/syft#output-formats"
        ;;
      "vat_response_lineage.json")
        PREDICATE_TYPE="https://vat.dso.mil/api/p1/predicate/beta1"
        ;;
      "hardening_manifest.json")
        PREDICATE_TYPE="https://repo1.dso.mil/dsop/dccscr/-/raw/master/hardening%20manifest/README.md"
        ;;
      *)
        PREDICATE_TYPE=""
        ;;
    esac

    if [ -n "$PREDICATE_TYPE" ]; then
      echo "INFO attesting $PREDICATE_TYPE $ARTIFACT_FILE ($PLATFORM)"
      DOCKER_CONFIG="$HOME/.docker" cosign attest \
        --predicate="$ARTIFACT_FILE" \
        --type="$PREDICATE_TYPE" \
        --key="$KMS_KEY_SHORT_ARN" \
        --certificate="$COSIGN_CERT" \
        --tlog-upload=false \
        "$REGISTRY_PUBLISH_URL/$IMAGE_NAME@$MANIFEST_LIST_SHA"
    fi
  done
done

# sign after uploading attestations
echo "INFO signing $REGISTRY_PUBLISH_URL/$IMAGE_NAME@$MANIFEST_LIST_SHA"
DOCKER_CONFIG="$HOME/.docker" cosign sign \
  --key="$KMS_KEY_SHORT_ARN" \
  --certificate="$COSIGN_CERT" \
  --tlog-upload=false \
  "$REGISTRY_PUBLISH_URL/$IMAGE_NAME@$MANIFEST_LIST_SHA"
