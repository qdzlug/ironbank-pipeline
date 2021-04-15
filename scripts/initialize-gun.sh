#!/bin/bash
#####
# This script is used to initialize Notary GUNs
#
# Usage:
# export NOTARY_AUTH=$(echo -n "exampleuser:examplepassword" | base64)
# ./initialize-gun.sh registry1.dso.mil/ironbank/project/image
#
# Where exampleuser:examplepassword are your harbor credentials
#####

set -euo pipefail

# Notary environment
NOTARY_ROOT_PASSPHRASE=$(openssl rand -base64 32)
NOTARY_SNAPSHOT_PASSPHRASE=$(openssl rand -base64 32)
NOTARY_TARGETS_PASSPHRASE=$(openssl rand -base64 32)

export NOTARY_ROOT_PASSPHRASE
export NOTARY_SNAPSHOT_PASSPHRASE
export NOTARY_TARGETS_PASSPHRASE

# Vault environment
export VAULT_ADDR="${VAULT_ADDR:-https://vault.admin.dso.mil}"
export VAULT_NAMESPACE="${VAULT_NAMESPACE:-notary}"

notary_url="${NOTARY_URL:-https://notary.dso.mil}"

# This designates the current revision of our targets keys.  This should be iterated upon target key rotation.  This should also be updated in the pipeline.
targetrev="${NOTARY_TARGETS_CURRENT_REVISION:-0}"
rootrev="${NOTARY_ROOT_CURRENT_REVISION:-0}"
rootkeyloc="rootkey/$rootrev"

trustdir=$(mktemp -d)

script_help() {
  echo
  echo "Please provide a GUN to initialize (e.g. registry1.dso.mil/ironbank/redhat/ubi/ubi)"
  echo "You may provide a single GUN or a file containing a list of newline-delimited GUNs"
  echo "NOTE: The GUN MUST MATCH the 'name' attirbute of the hardening_manifest.yaml for the image being initialized prefixed with the target registry url (e.g. registry1.dso.mil/<name>)"
}

if [ -z "${1:-}" ]; then
  script_help
  exit 1
fi

is_installed() {
  if ! command -v "${1}" >/dev/null; then
    echo
    echo "${1} must be installed before continuing, exiting"
    exit 1
  fi
}

clean() {
  # Clean up trustdir
  rm -rf -- "$trustdir"
}

import_root_key() {
  echo
  echo "==============================="
  echo " Retrieve root key from Vault "
  echo "==============================="
  echo

  # Login to Vault
  VAULT_TOKEN=$(vault login -token-only -method=userpass username=notary-admin)
  export VAULT_TOKEN

  # Retrieve root key
  vault kv get -field=rootkey "/kv/il2/notary/admin/$rootkeyloc" | notary -v -s "$notary_url" -d "$trustdir" key import /dev/stdin --role=root
}

init_gun() {
  gun=$1
  echo
  echo "==============================="
  echo "Initializing GUN $gun in Notary"
  echo "==============================="
  echo

  init_done=0
  delegation_done=0
  for i in $(seq 1 5); do
    # Initialize GUN with root key
    if [ "$init_done" -eq 0 ]; then
      if ! notary init "$gun" -p -d "$trustdir" -s "$notary_url"; then
        echo "WARNING: notary error or target key already exists for $gun, retrying"
        echo ""
        sleep 5
        continue
      fi
    fi
    init_done=1

    # Add delegation key. `delegation.crt` is already on-disk
    if [ "$delegation_done" -eq 0 ]; then
      if ! notary delegation add -s "$notary_url" -p -d "$trustdir" "$gun" targets/releases delegation.crt --all-paths; then
        echo "WARNING: notary error, retrying"
        echo ""
        sleep 5
        continue
      fi
    fi
    delegation_done=1

    # Rotate snapshot keys to be managed by notary server
    if ! notary key rotate "$gun" snapshot -r -d "$trustdir" -s "$notary_url"; then
      echo "WARNING: notary error, retrying"
      echo ""
      sleep 5
      continue
    fi

    # Place target key inVault at a location determined by the GUN
    decryptedkey=$(notary key export -d "$trustdir/" --gun "$gun" | sed '/:/d' | openssl ec -passin env:NOTARY_TARGETS_PASSPHRASE)

    echo -n "$decryptedkey" | vault kv put "/kv/il2/notary/admin/targets/$targetrev/$gun" key=-

    # Success, break from loop
    return 0
  done

  return 1
}

is_installed openssl
is_installed notary
is_installed vault

# Set NOTARY_AUTH if not set
if [ -z "${NOTARY_AUTH:-}" ]; then
  echo
  echo "Enter registry1.dso.mil username: "
  read -r -s username
  echo "Enter registry1.dso.mil password: "
  read -r -s password
  NOTARY_AUTH=$(echo -n "$username:$password" | base64)
  export NOTARY_AUTH
fi

import_root_key

while [[ $# -gt 0 ]]; do
  key="$1"
  case "$key" in
    -f | --file)
      if [ -z "$2" ]; then
        echo
        echo "Must provide argument for -f"
        exit 1
      fi
      filename="$2"
      while IFS= read -r gun; do
        init_gun "$gun"
      done <"$filename"
      exit 0
      ;;
    -h | --help)
      script_help
      exit 0
      ;;
    *)
      init_gun "$1"
      exit 0
      ;;
  esac
done

# Clean
trap clean EXIT
