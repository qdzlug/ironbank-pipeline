#!/bin/bash
set -Eeuo pipefail

echo "${IB_CONTAINER_GPG_KEY}" | base64 -d >key

# Gather info for scan-metadata.json
GPG_VERSION_INFO=$(gpg --version | grep "gpg")

if [[ "${DISTROLESS:-}" ]]; then
  ANCHORE_VERSION=$(sed 's/"//g' "${ANCHORE_VERSION_FILE}")
  TWISTLOCK_VERSION=$(sed 's/"//g' "${TWISTLOCK_VERSION_FILE}" | cut -d" " -f3)
else
  OPENSCAP_VERSION=$(<"${OPENSCAP_VERSION_FILE}")
  ANCHORE_VERSION=$(sed 's/"//g' "${ANCHORE_VERSION_FILE}")
  TWISTLOCK_VERSION=$(sed 's/"//g' "${TWISTLOCK_VERSION_FILE}" | cut -d" " -f3)
fi

#- OPENSCAP_VERSION=$(<"${OPENSCAP_VERSION}"")
GPG_PUB_KEY=$(awk '{printf "%s\\n", $0}' "${IB_CONTAINER_GPG_PUBKEY}")

# Create manifest.json
export IMAGE_VERSION
export CI_COMMIT_SHA
IMAGE_ACCREDITATION=$(jq -r .accreditation "${ARTIFACT_STORAGE}/vat/vat_response.json")
export IMAGE_ACCREDITATION
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
  "approval": env.IMAGE_ACCREDITATION,
  "image": {
    "digest": env.DIGEST_TO_SCAN
  },
  "pgp": {
    "publicKey": env.GPG_PUB_KEY,
    "version": env.GPG_VERSION_INFO
  },
  "git": {
    "branch": env.CI_COMMIT_BRANCH,
    "commit": env.COMMIT_SHA_TO_SCAN
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
}' >"${ARTIFACT_DIR}/scan-metadata.json"
cat "${ARTIFACT_DIR}/scan-metadata.json"
# Create manifest.json

export DOCKER_REFERENCE="${IMAGE_TO_SCAN}@${DIGEST_TO_SCAN}"

if [[ $IMAGE_TO_SCAN == *"ironbank-staging"* ]]; then
  export DOCKER_REFERENCE="${REGISTRY_URL_PROD}/${IMAGE_NAME}:${IMAGE_VERSION}@${DIGEST_TO_SCAN}"
fi

jq -n '
{
  "image": env.DOCKER_REFERENCE,
  "timestamp": env.BUILD_DATE_TO_SCAN,
  "git": {
    "hash": env.COMMIT_SHA_TO_SCAN,
    "branch": env.CI_COMMIT_BRANCH
  },
  "tools": {
    "anchore": {
      "version": env.ANCHORE_VERSION
    },
    "twistlock": {
      "version": env.TWISTLOCK_VERSION
    },
    "openSCAP": {
      "version": env.OPENSCAP_VERSION
    }
  }
}' >"${ARTIFACT_DIR}/reports/documentation.json"
cat "${ARTIFACT_DIR}/reports/documentation.json"
