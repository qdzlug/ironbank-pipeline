#!/bin/bash
set -Eeuo pipefail

# wrap the setup jobs in a shell script to support pipefail

## branch-check
mkdir -p "${ARTIFACT_DIR}"
if [[ "${CI_COMMIT_BRANCH}" == "master" || "${CI_COMMIT_BRANCH}" == "development" ]] && [[ "${CI_COMMIT_REF_PROTECTED}" != true ]]; then
  echo "This pipeline is running on an unprotected '${CI_COMMIT_BRANCH}' branch. Please protect '${CI_COMMIT_BRANCH}' before running the pipeline on this branch"
  echo "Exiting"
  exit 1
fi
if [[ "${CI_COMMIT_BRANCH}" == "master" ]] && "${STAGING_BASE_IMAGE}"; then
  echo "'STAGING_BASE_IMAGE' cannot be set on a 'master' branch."
  echo "Exiting"
  exit 1
fi

## load-scripts
if [[ -z "${STAGING_PIPELINE:-}" ]]; then
  echo "Searching for ci-artifacts dir"
  files_found=$(find . -name "ci-artifacts" -type d)
  echo "Searching for symlinks"
  links_found=$(find . -type l)
  echo "Validating symlinks"
  if [[ $links_found != "" ]]; then exit 1; fi
  echo "Validating files"
  if [[ $files_found != "" ]]; then echo "${files_found} was found"; fi
else
  echo "STAGING_PIPELINE var exists, skipping pre-check"
fi
mkdir -p "${PIPELINE_REPO_DIR}"
if [[ ${LOGLEVEL:-} == "DEBUG" ]]; then
  echo "Running pipeline for project branch: ${CI_COMMIT_BRANCH}";
  echo "Cloning pipeline branch: ${TARGET_BRANCH}";
fi
git clone -q --depth 1 --branch "${TARGET_BRANCH}" "${CI_SERVER_URL}/ironbank-tools/ironbank-pipeline.git" "${PIPELINE_REPO_DIR}"
git clone -q --depth 1 --branch "${MODULES_TAG}" "${CI_SERVER_URL}/ironbank-tools/${MODULES_PROJECT}.git" "${MODULES_CLONE_DIR}"
rm -rf "${PIPELINE_REPO_DIR}/.git"
rm -rf "${MODULES_CLONE_DIR}/.git"

## setup-modules
source "$(poetry env info -C "${MODULES_DEPS_PATH}" --path)"/bin/activate
poetry install -C "${MODULES_PACKAGE_PATH}" --only-root

## image_inspect.py
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/image_inspect.py"

## lint
set +e
( python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/lint_jobs.py"; ) || (($?==100 ? 1 : 0)) && echo "lint OK"
set -e

## trufflehog
git config --global --add safe.directory "${CI_PROJECT_DIR}"
python3 "${PIPELINE_REPO_DIR}/pipeline1/0-setup/trufflehog.py"
