#!/bin/bash
export ARTIFACT_DIR="."
mkdir -p "$ARTIFACT_DIR/external-resources"
mkdir -p "$ARTIFACT_DIR/images"
export LOCALTEST='true'
export S3_ACCESS_KEY_test=''
export S3_SECRET_KEY_test=''
export S3_ACCESS_KEY_your_id_here=''
export S3_SECRET_KEY_your_id_here=''
export CREDENTIAL_USERNAME_your_id_here=''
export CREDENTIAL_PASSWORD_your_id_here=''
