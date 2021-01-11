#!/bin/bash
set -Eeo pipefail

dnf install jq -y
echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key
mkdir -p tmp_gpg "${ARTIFACT_DIR}/reports"

# Gather info for scan-metadata.json
GPG_VERSION_INFO=$(gpg --version | grep "gpg")

if [[ "${DISTROLESS:-}" ]]; then
  ANCHORE_VERSION=$(cat "${ANCHORE_VERSION_FILE}" | sed 's/"//g')
  TWISTLOCK_VERSION=$(cat "${TWISTLOCK_VERSION_FILE}" | sed 's/"//g')
else
  OPENSCAP_VERSION=$(cat "${OPENSCAP_VERSION_FILE}")
  ANCHORE_VERSION=$(cat "${ANCHORE_VERSION_FILE}" | sed 's/"//g')
  TWISTLOCK_VERSION=$(cat "${TWISTLOCK_VERSION_FILE}" | sed 's/"//g')
fi

#- OPENSCAP_VERSION=$(cat ${OPENSCAP_VERSION})
GPG_PUB_KEY=$(awk '{printf "%s\\n", $0}' "${IB_CONTAINER_GPG_PUBKEY}")

# Create manifest.json
export IMAGE_VERSION
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
export CI_PIPELINE_ID
TIMESTAMP="$(date --utc '+%FT%T.%3NZ')"
export TIMESTAMP

jq -n '
{
  "buildTag": env.IMAGE_VERSION,
  "buildNumber": env.CI_PIPELINE_ID,
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

export DOCKER_REFERENCE="${REGISTRY_URL}/${IMAGE_NAME}:${IMAGE_VERSION}@${IMAGE_PODMAN_SHA}"

jq -n '
{
  "image": env.DOCKER_REFERENCE,
  "timestamp": env.TIMESTAMP,
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
