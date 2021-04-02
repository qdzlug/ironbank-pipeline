#!/bin/bash
set -Eeuo pipefail

if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project' && [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects unless DOCKER_AUTH_CONFIG_TEST is set..."
  exit 1
fi

NOTARY_DELEGATION_PASSPHRASE=$(openssl rand -base64 32)
export NOTARY_DELEGATION_PASSPHRASE

echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >>staging_auth.json

staging_image="${STAGING_REGISTRY_URL}/${IMAGE_NAME}"
gun="${REGISTRY_URL}/${IMAGE_NAME}"

echo "Logging into vault"
# Grab the vault token
vault_token=$(jq --null-input --arg password "${VAULT_PASSWORD}" '{"password":$password}' |
  curl --silent \
    --fail \
    --data @- \
    --header "X-Vault-Request: true" \
    --header "X-Vault-Namespace: ${VAULT_NAMESPACE}/" \
    --request PUT "${VAULT_ADDR}/v1/auth/userpass/login/${VAULT_USERNAME}" |
  jq --raw-output '.auth.client_token')

echo "Importing key into notary"

for ((rev = "${NOTARY_DELEGATION_CURRENT_REVISION}"; rev >= 0; rev -= 1)); do

  vault_addr_full="${VAULT_ADDR}/v1/kv/il2/notary/pipeline/delegation/${rev}"

  # Grab the target key and import into notary
  delegation_key_data=$(curl --silent \
    --header "X-Vault-Request: true" \
    --header "X-Vault-Token: ${vault_token}" \
    --header "X-Vault-Namespace: ${VAULT_NAMESPACE}/" \
    --request GET "${vault_addr_full}")

  delegation_key=$(echo "${delegation_key_data}" | jq --raw-output '.data.delegationkey')

  if [ "${delegation_key:-}" != "null" ]; then
    echo "Found key: ${vault_addr_full}"
    break
  fi

done

if [ "${delegation_key:-}" = "null" ]; then
  echo "Could not find key for ${gun} - Please speak to an administrator"
  exit 1
fi

echo -n "${delegation_key}" | notary --trustDir "${trust_dir}" key import --role "delegation" --gun "${gun}" /dev/stdin
echo "Key imported"

if [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "${DOCKER_AUTH_CONFIG_PROD}" | base64 --decode >dest_auth.json
else
  echo "${DOCKER_AUTH_CONFIG_TEST}" | base64 --decode >dest_auth.json
fi

# Copy from staging to prod with each tag listed in descriptions.yaml
tags_file="${ARTIFACT_STORAGE}/preflight/tags.txt"
test -f "${tags_file}"

while IFS= read -r tag; do

  echo "Pulling ${tag}_manifest.json"
  skopeo inspect --authfile staging_auth.json --raw "docker://${staging_image}@${IMAGE_PODMAN_SHA}" >"${tag}_manifest.json"

  # "Be defensive and test it" ~Blake Burkhart
  echo "${IMAGE_PODMAN_SHA#sha256:} ${tag}_manifest.json" | sha256sum --check

  # Sign the image with the delegation key
  echo
  echo "Signing ${tag}_manifest.json with notary"

  notary --verbose --server "${NOTARY_URL}" --trustDir ${trust_dir} add --roles targets/releases --publish "${gun}" "${tag}" "${tag}_manifest.json"

  echo "Copy from staging to destination"
  echo skopeo copy --src-authfile staging_auth.json --dest-authfile dest_auth.json "docker://${staging_image}@${IMAGE_PODMAN_SHA}" "docker://${gun}:${tag}"
  skopeo copy --src-authfile staging_auth.json \
    --dest-authfile dest_auth.json \
    "docker://${staging_image}@${IMAGE_PODMAN_SHA}" \
    "docker://${gun}:${tag}"

  echo "======"

done <"${tags_file}"
