#!/bin/bash
set -Eeuo pipefail

if echo "${CI_PROJECT_DIR}" | grep -q -F 'pipeline-test-project' && [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "Skipping Harbor Upload. Cannot push to Harbor when working with pipeline test projects unless DOCKER_AUTH_CONFIG_TEST is set..."
  exit 1
fi

echo "${DOCKER_AUTH_CONFIG_STAGING}" | base64 -d >>staging_auth.json

# TODO: Confirm IM_NAME is hardening manifest
staging_image="${STAGING_REGISTRY_URL}/${IM_NAME}"
gun="${REGISTRY_URL}/${IM_NAME}"

# TODO: Use this instead
trust_dir="trust-dir-target/"

# Grab the delegation key from vault
# vault login -no-print=true -method=userpass username="${VAULT_STAGING_USERNAME}" password="${VAULT_STAGING_PASSWORD}"

# TODO Make dynamic based off naming scheme
# vault kv get -field=delegation.key kv/il2/notary/delegation1 >delegation.key

echo "Logging into vault"
# Grab the vault token
vault_token=$(jq --null-input --arg password $VAULT_STAGING_PASSWORD '{"password":$password}' | \
   curl --silent \
        --data @- \
        --header "X-Vault-Request: true" \
        --header "X-Vault-Namespace: $VAULT_STAGING_NAMESPACE/" \
        --request PUT "$VAULT_ADDR/v1/auth/userpass/login/$VAULT_STAGING_USERNAME" | \
   jq --raw-output '.auth.client_token')

vault_addr_full="$VAULT_ADDR/v1/kv/il2/notary/pipeline/data/$gun"
echo "Grabbing key from"
echo "    $vault_addr_full"

# Grab the target key and import into notary
echo "Importing key into notary"
curl --silent \
     --header "X-Vault-Request: true" \
     --header "X-Vault-Token: $vault_token" \
     --header "X-Vault-Namespace: $VAULT_STAGING_NAMESPACE/" \
     --request GET "$vault_addr_full" | \
     jq --raw-output '.data.data.targetkey' | \
     notary -d trust-dir-delegate/ key import /dev/stdin

echo "Key imported"

if [ -z "${DOCKER_AUTH_CONFIG_TEST:-}" ]; then
  echo "${DOCKER_AUTH_CONFIG_PROD}" | base64 -d >dest_auth.json
else
  echo "${DOCKER_AUTH_CONFIG_TEST}" | base64 -d >dest_auth.json
fi

# Copy from staging to prod with each tag listed in descriptions.yaml
echo "Read the tags"
tags_file="${ARTIFACT_STORAGE}/preflight/tags.txt"
test -f "$tags_file"


while IFS= read -r tag; do

  echo "Pulling ${tag}_manifest.json"
  skopeo inspect --authfile staging_auth.json --raw "docker://${staging_image}:${tag}" >"${tag}_manifest.json"

  cat "${tag}_manifest.json"

  # Sign the image with the delegation key
  echo
  echo "Signing with notary"
  notary -v -s "${NOTARY_URL}" -d trust-dir-delegate add -p "$gun" "${tag}" "${tag}_manifest.json"

  echo "Copy from staging to destination"
  skopeo copy --src-authfile staging_auth.json --dest-authfile dest_auth.json \
    "docker://${staging_image}@${IMAGE_PODMAN_SHA}" \
    "docker://${REGISTRY_URL}/${IM_NAME}:${tag}"

  echo "======"

done <"${tags_file}"
