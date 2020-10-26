#!/bin/bash
set -Eeo pipefail
dnf install jq -y
podman load -i "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}"
echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key
mkdir -p tmp_gpg "${ARTIFACT_DIR}/reports"
# Gather info for scan-metadata.json
GPG_VERSION_INFO=$(gpg --version | grep "gpg")
# TODO add anchore endpoint
#- ANCHORE_VERSION=$(curl -k ${anchore_server_address}/version)
if [[ "${DISTROLESS:-}" ]]; then
  ANCHORE_VERSION=$(cat "${ANCHORE_VERSION_FILE}" | sed 's/"//g')
  TWISTLOCK_VERSION=$(cat "${TWISTLOCK_VERSION_FILE}" | sed 's/"//g')
else
  OPENSCAP_VERSION=$(cat "${OPENSCAP_VERSION_FILE}")
  ANCHORE_VERSION=$(cat "${ANCHORE_VERSION_FILE}" | sed 's/"//g')
  TWISTLOCK_VERSION=$(cat "${TWISTLOCK_VERSION_FILE}" | sed 's/"//g')
fi
#- OPENSCAP_VERSION=$(cat ${OPENSCAP_VERSION})
IMAGE_TAR_SHA=$(sha256sum "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" | grep -E '^[a-zA-Z0-9]+' -o)
IMAGE_PODMAN_SHA=$(podman inspect --format '{{.Digest}}' "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}")
GPG_PUB_KEY=$(awk '{printf "%s\\n", $0}' "${IB_CONTAINER_GPG_PUBKEY}")
# Create manifest.json

export IMG_VERSION
export CI_COMMIT_SHA
export IMAGE_APPROVAL_STATUS
export IMAGE_TAR_SHA
export IMAGE_PODMAN_SHA
export GPG_PUB_KEY
export GPG_VERSION_INFO
export CI_COMMIT_BRANCH
export TWISTLOCK_VERSION
export OPENSCAP_VERSION
export ANCHORE_VERSION
export CI_COMMIT_BRANCH
timestamp="$(date +%FT%T)"
export timestamp
jq -n '
{
  "buildTag": env.IMG_VERSION,
  "buildNumber": env.CI_COMMIT_SHA,
  "approval": env.IMAGE_APPROVAL_STATUS,
  "image": {
    "digest": env.IMAGE_TAR_SHA,
    "sha256": env.IMAGE_PODMAN_SHA
  },
  "pgp": {
    "publicKey": env.GPG_PUB_KEY,
    "version": env.GPG_VERSION_INFO
  },
  "git": {
    "branch": env.CI_COMMIT_BRANCH,
    "commit": env.CI_COMMIT_SHA
  },
  "reports": {
    "twistlock": {
      "version": env.TWISTLOCK_VERSION
    },
    "openSCAP": {
      "version": env.OPENSCAP_VERSION
    },
    "anchore": {
      "version": env.ANCHORE_VERSION
    }
  }
}' >scan-metadata.json
cat scan-metadata.json
mv scan-metadata.json "${ARTIFACT_DIR}"
# Create manifest.json

jq -n '
{
  "timestamp": env.timestamp,
  "git": {
    "hash": env.CI_COMMIT_SHA,
    "branch": env.CI_COMMIT_BRANCH
  },
  "tools": {
    "anchore": {
      "version": env.ANCHORE_VERSION
    },
    "twistlock": {
      "version": env.ANCHORE_VERSION
    },
    "openSCAP": {
      "version": env.OPENSCAP_VERSION
    }
  }
}' >documentation.json
cat documentation.json
mv documentation.json "${ARTIFACT_DIR}/reports"
