#!/bin/bash
# Used for adding delegation cert to new GUN (run locally, never in pipeline)
set -xe

# Set gun as argmuent to script, i.e. `bash local-delegation.sh registry1.dsop.io/ironbank/redhat/ubi8/ubi:8.2`
gun=${1}
notary_url=https://notary.dsop.io

#TODO handle NOTARY_AUTH?
export NOTARY_ROOT_PASSPHRASE=$(openssl rand -base64 32)
export NOTARY_SNAPSHOT_PASSPHRASE=$(openssl rand -base64 32)
export NOTARY_TARGETS_PASSPHRASE=$(openssl rand -base64 32)

# Import root key to notary
notary -v -s "$notary_url" -d trust-dir-root key import root.key --role=root

# Rotate the target key to ensure the delegate user never needs it
notary -v -s "$notary_url" -d trust-dir-root key rotate "$gun" targets

# Rotate the snapshot key to ensure the delegate user never needs it
notary -v -s "$notary_url" -d trust-dir-root key rotate "$gun" snapshot --server-managed

# Trust the new delegate for the gun
# This works even if the GUN doesn't exist yet
notary -v -s "$notary_url" -d trust-dir-root delegation add -p "$gun" targets/releases delegation.crt --all-paths

# Delete trust dir, discarding the generated target key and imported root key
rm -r trust-dir-root
