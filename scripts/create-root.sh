#!/bin/bash

###
# This script is meant to only be run once every 10 years.  Once we have a root key in Vault for Notary signing
# we'll want to continue to use it until the time comes to rotate it upon expiration (10 years).  When that time
# comes, the team in charge of maintaining the Vault cluster will need to grant "Update" permissions for the notary-admin
# user.
###

set -ue

#notary_url='https://notary.dev.dsop.io'
vault_url='https://cubbyhole.staging.dso.mil'
vault_namespace='il2-ironbank-ns'

alias vault=$(docker exec -it vault -- vault &2> /dev/null)

# Get distro
os=$(uname)

# Install notary if not present
if ! command -v notary; then
    if [ "$(uname)" = "Darwin" ]; then
        curl -O https://github.com/theupdateframework/notary/releases/download/v0.6.1/notary-Darwin-amd64
        mv notary-Linux-amd64 /usr/local/bin/notary
    else
        curl -O https://github.com/theupdateframework/notary/releases/download/v0.6.1/notary-Linux-amd64
        mv notary-Linux-amd64 /usr/local/bin/notary
    fi
fi

if ! command -v openssl; then
    echo "openssl must be installed"
    exit
fi

if ! command -v openssl; then
    echo "notary must be installed"
    exit
fi

# Sign into registry1
echo ""
echo "========================"
echo " Logging into registry1 "
echo "========================"
echo ""
docker login registry1.dso.mil

# Create vault container
docker run --entrypoint=cat --rm --name vault registry1.dso.mil/ironbank/hashicorp/vault/vault:1.6.3 &

# Generate root key
mkdir root
echo ""
echo "====================="
echo " Generating root key "
echo "====================="
echo ""

openssl genrsa -out root/root.key 4096

# Generate CSR for certificate that will function as CA
openssl req -new -sha256 -key root/root.key -out root/root.csr -subj "/C=US/ST=Colorado/L=Colorado Springs/O=Platform1/OU=Iron Bank/CN=ironbank.dso.mil/emailAddress=ironbank@dso.mil"

# Assign root key as Notary key
#notary -v -s "$notary_url" -d trust-dir-root key import root/root.key --role=root

# Add root key to Vault
echo ""
echo "=========================="
echo " Adding root key to Vault "
echo "=========================="
echo ""
vault login -method=userpass -namespace=$vault_namespace -address=$vault_url username=notary-admin

# Reset password.  Write it down first.
echo "please set a new notary-admin user password: "
read -s adminpass
vault write -address=$vault_url -namespace=$vault_namespace auth/userpass/users/notary-admin/password password=$adminpass

# Add root key to Vault
cat root/root.key | vault kv put -address=$vault_url -namespace=$vault_namespace /kv/il2/notary/admin/rootkey-test2 rootkey-test2=-

# Destroy root key
rm -rf root/
