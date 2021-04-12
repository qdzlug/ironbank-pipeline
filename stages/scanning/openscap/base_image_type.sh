#!/bin/bash
set -Eeuo pipefail
podman load -i "${ARTIFACT_STORAGE}"/build/"${CI_PROJECT_NAME}"-"${CI_PIPELINE_ID}".tar
DOCKER_IMAGE_PATH=$(podman images --noheading | awk '{print $3}')
export DOCKER_IMAGE_PATH
BASE_IMAGE_TYPE=$(podman inspect -f '{{index .Labels "com.redhat.component"}}' "${DOCKER_IMAGE_PATH}")
if [[ "${BASE_IMAGE_TYPE}" == "" ]]; then
  BASE_IMAGE_TYPE=$(podman inspect -f '{{index .Labels "os_type"}}' "${DOCKER_IMAGE_PATH}")
  if [[ "${BASE_IMAGE_TYPE}" == "" ]]; then
    BASE_IMAGE_TYPE=$(podman inspect -f '{{index .Labels "mil.dso.ironbank.os-type"}}' "${DOCKER_IMAGE_PATH}")
    if [[ "${BASE_IMAGE_TYPE}" == "" ]]; then
      labels=$(podman inspect -f '{{index .Labels}}' "${DOCKER_IMAGE_PATH}")
      echo "Unknown image type. Can't choose security guide. labels: ${labels}"
      exit 1
    fi
  fi
fi

echo "Base Image Type: ${BASE_IMAGE_TYPE}"

export BASE_IMAGE_TYPE
