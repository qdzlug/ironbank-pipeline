#!/bin/bash
#####
#
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

if [ -z "$1" ]; then
    echo "Please provide a GUN to initialize (i.e registry1.dso.mil/ironbank/redhat/ubi/ubi:8.3)"
    exit 1
fi

echo ""
echo "==============================="
echo " Retrieve root key from Vault "
echo "==============================="
echo ""
vault login -method=userpass -namespace=$vault_namespace -address=$vault_url username=notary-admin

vault kv get -field=rootkey-test2 -address=$vault_url -namespace=$vault_namespace /kv/il2/notary/admin/rootkey-test2 | notary -v -s $notary_url -d trust-dir-root key import /dev/stdin --role=root

echo "Initialize GUN ${1} in Notary"
notary init -d trust-dir-root -s $notary_url ${1}

# Clean up root key
rm -rf root.key trust-dir-root
