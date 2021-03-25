#!/bin/bash
#####
# This script is used to initialize Notary GUNs
#
# Usage:
# export NOTARY_AUTH=$(echo "exampleuser:examplepassword" | base64)
# ./initialize-gun.sh registry1.dso.mil/ironbank/project/image
#
# Where exampleuser:examplepassword are your harbor credentials
#####

export NOTARY_ROOT_PASSPHRASE=$(openssl rand -base64 32)
export NOTARY_SNAPSHOT_PASSPHRASE=$(openssl rand -base64 32)
export NOTARY_TARGETS_PASSPHRASE=$(openssl rand -base64 32)

notary_url='https://notary.dso.mil'
vault_url='https://cubbyhole.staging.dso.mil'
vault_namespace='il2-ironbank-ns'

script_help() {
    echo
    echo "Please provide a GUN to initialize (e.g. registry1.dso.mil/ironbank/redhat/ubi/ubi:8.3)"
    echo "You may provide a single GUN or a file containing a list of newline-delimited GUNs"
    echo "NOTE: The GUN MUST MATCH the 'name' attirbute of the hardening_manifest.yaml for the image being initialized prefixed with the target registry url (e.g. registry1.dso.mil/<name>)"
}

if [ -z "$1" ]; then
    script_help
    exit 1
fi

# Install notary if not present
if ! command -v notary; then
    if [ "$(uname)" = "Darwin" ]; then
        curl -O https://github.com/theupdateframework/notary/releases/download/v0.6.1/notary-Darwin-amd64
        mv notary-Darwin-amd64 /usr/local/bin/notary
    elif [ "$(uname)" = "Linux" ]; then
        curl -O https://github.com/theupdateframework/notary/releases/download/v0.6.1/notary-Linux-amd64
        mv notary-Linux-amd64 /usr/local/bin/notary
    else
        echo
        echo "Unsupported OS type, exiting"
        exit 1
    fi
fi

if ! command -v jq; then
    echo
    echo "jq must be installed before continuing, exiting"
    exit 1
fi

if [ -z "$1" ]; then
    echo
    echo "Please provide a GUN to initialize (i.e registry1.dso.mil/ironbank/redhat/ubi/ubi:8.3)"
    echo "NOTE: This MUST MATCH the 'name' attirbute of the hardening_manifest.yaml for the image being initialized."
    exit 1
fi

import_root_key() {
    echo
    echo "==============================="
    echo " Retrieve root key from Vault "
    echo "==============================="
    echo

    # Login to Vault
    vault login -method=userpass -namespace=$vault_namespace -address=$vault_url username=notary-admin

    # Retrieve root key
    vault kv get -field=rootkey -address=$vault_url -namespace=$vault_namespace /kv/il2/notary/admin/rootkey | notary -v -s $notary_url -d trust-dir key import /dev/stdin --role=root
}

init_gun() {
    gun=$1
    echo
    echo "==============================="
    echo "Initializing GUN $gun in Notary"
    echo "==============================="
    echo

    # Initialize GUN with root key
    notary init $gun -p -d trust-dir -s $notary_url

    # Rotate snapshot keys to be managed by notary server
    notary key rotate $gun snapshot -r -d trust-dir -s $notary_url

    # Parse target keyid value out of targets.json
    keyid=$(cat "trust-dir/tuf/$gun/metadata/targets.json" | jq -r '.signatures[0].keyid')

    # Place target key in Vault at a location determined by the GUN
    cat "trust-dir/private/$keyid.key" | vault kv put -address=$vault_url -namespace=$vault_namespace "/kv/il2/notary/pipeline/$gun" targetkey=-
}

import_root_key

while [[ $# -gt 0 ]]; do
    key="$1"
    case $key in
        -f|--file)
            if [ -z "$2" ]; then
                echo
                echo "Must provide argument for -f"
                exit 1
            fi
            filename="$2"
            while IFS= read -r gun; do
                init_gun $gun;
            done < $filename
            exit 0
            ;;
        -h|--help)
            script_help
            exit 0
            ;;
        *)
            init_gun $1
            exit 0
            ;;
    esac
done

# Clean up root key
rm -rf trust-dir
