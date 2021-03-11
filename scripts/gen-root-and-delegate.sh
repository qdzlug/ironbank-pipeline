#!/bin/bash
# Used for generating notary root key and x509 signing cert (run locally, never in pipeline)

set -xe

notary_url="https://notary.dso.mil"

# Create dirs for delegation and root key/cert
mkdir -p delegation root

# Generate root key (never to be seen by the light of day)
openssl genrsa -out root/root.key 4096
openssl req -new -sha256 -key root/root.key -out root/root.csr -subj "/C=US/ST=Colorado/L=Colorado Springs/O=Platform1/OU=Iron Bank/CN=ironbank.dso.mil/emailAddress=ironbank@dsop.io"

# Self sign?
openssl x509 -req -sha256 -days 3650 -in root/root.csr -signkey root/root.key -out root/root.crt
notary -v -s "$notary_url" -d trust-dir-root key import root/root.key --role=root

# Generate new RSA key
openssl genrsa -out delegation/delegation.key 4096
# Generate signing request with P1 org info
openssl req -new -sha256 -key delegation/delegation.key -out delegation/delegation.csr -subj "/C=US/ST=Colorado/L=Colorado Springs/O=Platform1/OU=Iron Bank/CN=ironbank.dso.mil/emailAddress=ironbank@dsop.io"
# Generate x509 Certificate
openssl x509 -req -sha256 -days 1095 -in delegation/delegation.csr -signkey delegation/delegation.key -out delegation/delegation.crt
