#!/bin/bash
set -Eeo pipefail
dnf install jq -y
podman load -i "${ARTIFACT_STORAGE}/build/${IMAGE_FILE}.tar" "${STAGING_REGISTRY_URL}/${IM_NAME}:${IMG_VERSION}"
echo "${IB_CONTAINER_GPG_KEY}" | base64 -d > key
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

cat <<EOF > scan-metadata.json
{
    "buildTag": "",
    "buildNumber": "",
    "approval": "",
    "image": {
        "digest": "",
        "sha256": ""
    },
    "pgp": {
        "publicKey": "",
        "version":""
    },
    "git": {
        "branch": "",
        "commit": ""
    },
    "reports": {
        "twistlock": {
            "version": ""
        },
        "openSCAP": {
            "version": ""
        },
        "anchore": {
            "version": ""
        }
    }
}
EOF
echo `jq --arg IMG_VERSION "${IMG_VERSION}" '.buildTag = $IMG_VERSION' scan-metadata.json` > scan-metadata.json
echo `jq --arg CI_COMMIT_SHA "${CI_COMMIT_SHA}" '.buildNumber = $CI_COMMIT_SHA' scan-metadata.json` > scan-metadata.json
echo `jq --arg IMAGE_APPROVAL_STATUS "${IMAGE_APPROVAL_STATUS}" '.approval = $IMAGE_APPROVAL_STATUS' scan-metadata.json` > scan-metadata.json
echo `jq --arg IMAGE_TAR_SHA "${IMAGE_TAR_SHA}" '.image.digest = $IMAGE_TAR_SHA' scan-metadata.json` > scan-metadata.json
echo `jq --arg IMAGE_PODMAN_SHA "${IMAGE_PODMAN_SHA}" '.image.sha256 = $IMAGE_PODMAN_SHA' scan-metadata.json` > scan-metadata.json
echo `jq --arg GPG_PUB_KEY "${GPG_PUB_KEY}" '.pgp.publicKey = $GPG_PUB_KEY' scan-metadata.json` > scan-metadata.json
echo `jq --arg GPG_VERSION_INFO "${GPG_VERSION_INFO}" '.pgp.version = $GPG_VERSION_INFO' scan-metadata.json` > scan-metadata.json
echo `jq --arg CI_COMMIT_BRANCH "${CI_COMMIT_BRANCH}" '.git.branch = $CI_COMMIT_BRANCH' scan-metadata.json` > scan-metadata.json
echo `jq --arg CI_COMMIT_SHA "${CI_COMMIT_SHA}" '.git.commit = $CI_COMMIT_SHA' scan-metadata.json` > scan-metadata.json
echo `jq --arg TWISTLOCK_VERSION "${TWISTLOCK_VERSION}" '.reports.twistlock.version = $TWISTLOCK_VERSION' scan-metadata.json` > scan-metadata.json
echo `jq --arg OPENSCAP_VERSION "${OPENSCAP_VERSION}" '.reports.openSCAP.version = $OPENSCAP_VERSION' scan-metadata.json` > scan-metadata.json
echo `jq --arg ANCHORE_VERSION "${ANCHORE_VERSION}" '.reports.anchore.version = $ANCHORE_VERSION' scan-metadata.json` > scan-metadata.json
jq . scan-metadata.json > scan-metadata.tmp && mv scan-metadata.tmp scan-metadata.json
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
