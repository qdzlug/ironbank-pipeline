#!/bin/bash
set -Eeuo pipefail
podman load -i "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}"
echo "${IB_CONTAINER_GPG_KEY}" | base64 -d > key
mkdir -p tmp_gpg "${ARTIFACT_DIR}/reports"
# Gather info for scan-metadata.json
GPG_VERSION_INFO=$(gpg --version | grep "gpg")
# TODO add anchore endpoint
#- ANCHORE_VERSION=$(curl -k ${anchore_server_address}/version)
OPENSCAP_VERSION=$(cat "${OPENSCAP_VERSION_FILE}")
ANCHORE_VERSION=$(cat "${ANCHORE_VERSION_FILE}" | sed 's/"//g')
TWISTLOCK_VERSION=$(cat "${TWISTLOCK_VERSION_FILE}" | sed 's/"//g')
#- OPENSCAP_VERSION=$(cat ${OPENSCAP_VERSION})
IMAGE_TAR_SHA=$(sha256sum "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" | grep -E '^[a-zA-Z0-9]+' -o)
IMAGE_PODMAN_SHA=$(podman inspect --format {{'.Digest'}} "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}")
GPG_PUB_KEY=$(awk '{printf "%s\\n", $0}' "${IB_CONTAINER_GPG_PUBKEY}")
# Create manifest.json

cat <<EOF > scan-metadata.json
{
    "buildTag": "${IMG_VERSION}",
    "buildNumber": "${CI_COMMIT_SHA}",
    "approval": "${IMAGE_APPROVAL_STATUS}",
    "image": {
        "digest": "${IMAGE_TAR_SHA}",
        "sha256": "${IMAGE_PODMAN_SHA}"
    },
    "pgp": {
        "publicKey": "${GPG_PUB_KEY}",
        "version":"${GPG_VERSION_INFO}"
    },
    "git": {
        "branch": "${CI_COMMIT_BRANCH}",
        "commit": "${CI_COMMIT_SHA}"
    },
    "reports": {
        "twistlock": {
            "version": "${TWISTLOCK_VERSION}"
        },
        "openSCAP": {
            "version": "${OPENSCAP_VERSION}"
        },
        "anchore": {
            "version": "${ANCHORE_VERSION}"
        }
    }
}
EOF
cat scan-metadata.json
mv scan-metadata.json "${ARTIFACT_DIR}"
# Create manifest.json

cat <<EOF > documentation.json
{
    "timestamp": "$(date +%FT%T)",
    "git": {
        "hash": "${CI_COMMIT_SHA}",
        "branch": "${CI_COMMIT_BRANCH}"
    },
    "tools": {
            "anchore": {
            "version": "${ANCHORE_VERSION}"
        },
            "twistlock": {
            "version": "${TWISTLOCK_VERSION}"
        },
            "openSCAP": {
            "version": "${OPENSCAP_VERSION}"
        }
    }
}
EOF
cat documentation.json
mv documentation.json "${ARTIFACT_DIR}/reports"
