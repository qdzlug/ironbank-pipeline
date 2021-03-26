#!/bin/bash
set -Eeuo pipefail

if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project' && [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects unless DOCKER_AUTH_CONFIG_TEST is set..."
  exit 1
fi

export NOTARY_TARGETS_PASSPHRASE=$(openssl rand -base64 32)
echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >>staging_auth.json

# TODO: Confirm IM_NAME is hardening manifest
staging_image="${STAGING_REGISTRY_URL}/${IM_NAME}"
gun="${REGISTRY_URL}/${IM_NAME}"
trust_dir="trust-dir-target/"

echo "Logging into vault"
# Grab the vault token
vault_token=$(jq --null-input --arg password $VAULT_STAGING_PASSWORD '{"password":$password}' | \
   curl --silent \
        --data @- \
        --header "X-Vault-Request: true" \
        --header "X-Vault-Namespace: $VAULT_NAMESPACE/" \
        --request PUT "$VAULT_ADDR/v1/auth/userpass/login/$VAULT_STAGING_USERNAME" | \
   jq --raw-output '.auth.client_token')

vault_addr_full="$VAULT_ADDR/v1/kv/il2/notary/pipeline/data/targets/0/$gun"
echo "Grabbing key from"
echo "    $vault_addr_full"

# Grab the target key and import into notary
echo "Importing key into notary"
curl --silent \
     --header "X-Vault-Request: true" \
     --header "X-Vault-Token: $vault_token" \
     --header "X-Vault-Namespace: $VAULT_NAMESPACE/" \
     --request GET "$vault_addr_full" | \
     jq --raw-output '.data.data.key' | \
     notary --trustDir "$trust_dir" key import /dev/stdin

echo "Key imported"

if [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "Prod config"
  echo "${DOCKER_AUTH_CONFIG_PROD}" | base64 --decode >dest_auth.json
else
  echo "Test config"
  echo "${DOCKER_AUTH_CONFIG_TEST}" | base64 --decode >dest_auth.json
fi

# Copy from staging to prod with each tag listed in descriptions.yaml
echo "Read the tags"
tags_file="${ARTIFACT_STORAGE}/preflight/tags.txt"
test -f "$tags_file"

echo "Testing the dest auth"
test -f dest_auth.json
echo "dest auth exists"

while IFS= read -r tag; do

  echo "Checking target keys"
  notary --server "${NOTARY_URL}" --trustDir "$trust_dir" list --roles targets "$gun"

  echo "Manually checking $trust_dir"
  ls -R "$trust_dir"

  echo "Pulling ${tag}_manifest.json"
  skopeo inspect --authfile staging_auth.json --raw "docker://${staging_image}:${IMAGE_PODMAN_SHA}" >"${tag}_manifest.json"

  cat "${tag}_manifest.json" | jq

  # Sign the image with the delegation key
  echo
  echo "Signing with notary"
  notary --verbose --server "${NOTARY_URL}" --trustDir $trust_dir add --publish "$gun" "${tag}" "${tag}_manifest.json"

  echo "Copy from staging to destination"
  echo skopeo copy --src-authfile staging_auth.json --dest-authfile dest_auth.json "docker://${staging_image}@${IMAGE_PODMAN_SHA}" "docker://${gun}:${tag}"
  skopeo copy --src-authfile staging_auth.json \
              --dest-authfile dest_auth.json \
              "docker://${staging_image}@${IMAGE_PODMAN_SHA}" \
              "docker://${gun}:${tag}"

  echo "======"

done <"${tags_file}"
