#!/bin/bash
# Used for generating notary root key and x509 signing cert (run locally, never in pipeline)
set -xe

# Start out with no keys when testing
rm -rf trust-dir-root delegation delegation.*

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
