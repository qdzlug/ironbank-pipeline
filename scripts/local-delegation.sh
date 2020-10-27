#!/bin/bash
# Used for generating notary root key and x509 signing cert (run locally, never in pipeline)
set -xe

# Start out with no keys when testing
rm -rf trust-dir-root delegation delegation.*

# These env variables must be set before running this
export NOTARY_AUTH="${NOTARY_SIGNER_AUTH}"
export NOTARY_ROOT_PASSPHRASE="${NOTARY_ROOT_PASSWORD}"
export NOTARY_DELEGATION_PASSPHRASE="${NOTARY_DELEGATION_PASSWORD}"
export NOTARY_TARGETS_PASSPHRASE="${NOTARY_TARGETS_PASSWORD}"
export NOTARY_SNAPSHOT_PASSPHRASE="${NOTARY_SNAPSHOT_PASSWORD}"

notary_url=https://notary.dsop.io

# Generate root key (never to be seen by the light of day)
notary -v -d trust-dir-root key generate --role=root
notary -d trust-dir-root key export -o root-key.pem

# Create dir for delegation key/cert
mkdir -p delegation

# Generate new RSA key
openssl genrsa -out delegation/delegation.key 2048
# Generate signing request with P1 org info
openssl req -new -sha256 -key delegation/delegation.key -out delegation/delegation.csr -subj "/C=US/ST=Colorado/L=Colorado Springs/O=Platform1/OU=Iron Bank/CN=repo1.dsop.io/emailAddress=ironbank@dsop.io"
# Generate x509 Certificate
openssl x509 -req -sha256 -days 365 -in delegation/delegation.csr -signkey delegation/delegation.key -out delegation/delegation.crt

# Rotate the snapshot key to ensure the delegate user never needs it
# A snapshot and target key will be generated for root, but I don't know if we need to archive them?
notary -v -s "${NOTARY_URL}" -d trust-dir-root key rotate "$gun" snapshot -r

# Trust the new delegate for the gun
# This works even if the GUN doesn't exist yet
notary -v -s "${NOTARY_URL}" -d trust-dir-root delegation add -p "$gun" targets/releases delegation/delegation.crt --all-paths
