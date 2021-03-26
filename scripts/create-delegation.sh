#!/bin/bash

###
#
# This script is meant to only be run once every 3 years.  Once we have a delegation key in Vault for Notary signing
# we'll want to continue to use it until the time comes to rotate it upon expiration (3 years).  When that time
# comes, the team in charge of maintaining the Vault cluster will need to grant "Update" permissions for the notary-admin
# user.
#
###

set -euo pipefail

#TODO change the default VAULT_ADDR when we have a prod endpoint
export VAULT_ADDR="${VAULT_ADDR:-https://cubbyhole.staging.dso.mil}"
export VAULT_NAMESPACE="${VAULT_NAMESPACE:-il2-ironbank-ns}"

rev="${NOTARY_DELEGATION_CURRENT_REVISION:-0}"
#TODO update this before putting into production to `delegation`
delegationkeyloc="delegation-test/$rev"
delegationdir=$(mktemp -d)

is_installed() {
    # Install notary if not present
    if ! command -v "${1}"; then
        echo
        echo "${1} must be installed before continuing, exiting"
        echo
        exit 1
    fi
}

clean() {
    rm -rf -- "$delegationdir"
}

is_installed openssl
is_installed vault
is_installed notary

echo
echo "==========================="
echo " Generating delegation key "
echo "==========================="
echo

openssl genrsa -out "$delegationdir/delegation.key" 4096

# Generate CSR for certificate that will function as CA
openssl req -new -sha256 -key "$delegationdir/delegation.key" -out "delegation.csr" -subj "/C=US/ST=Colorado/L=Colorado Springs/O=Platform1/OU=Iron Bank/CN=ironbank.dso.mil/emailAddress=ironbank@dso.mil"

# Add delegation key to Vault
echo
echo "=================================="
echo " Adding deletegation key to Vault "
echo "=================================="
echo
echo "Enter the initial notary-admin password"
export VAULT_TOKEN=$(vault login -token-only -method=userpass username=notary-admin)

# Change notary-admin password.  Write it down first.
echo
echo "Change notary-admin user password: "
echo
read -r -s adminpass
vault write auth/userpass/users/notary-admin/password password="$adminpass"

# Add delegation key to Vault
echo
echo "WARNING: By adding this delegation key to Vault, you are assigning the key generated by THIS RUN as our delegation key for the next 3 years.  Continue? [y|n]:"
echo

read confirm
if [ "$confirm" = "y" ]; then
    cat "$delegationdir/delegation.key" | vault kv put "/kv/il2/notary/pipeline/$delegationkeyloc" delegationkey=-
else
    echo
    echo "'y' not supplied, aborting"
    exit 0
fi

# Clean
trap clean EXIT
