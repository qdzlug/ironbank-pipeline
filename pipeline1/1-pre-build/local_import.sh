#!/bin/bash

# For local use
# This script exports environment variables neccessary to test downloader.py

# Exports local path to ARTIFACT_DIR variable
export ARTIFACT_DIR="."

# Creates external-resources directory for HTTP and S3 resources
mkdir -p "$ARTIFACT_DIR/external-resources"

# Creates images directory for images used in Dockerfile build
mkdir -p "$ARTIFACT_DIR/images"

# Credential placeholder variable to enable testing locally
export LOCALTEST='true'
export S3_ACCESS_KEY_test=''
export S3_SECRET_KEY_test=''
export S3_ACCESS_KEY_your_id_here=''
export S3_SECRET_KEY_your_id_here=''
export CREDENTIAL_USERNAME_your_id_here=''
export CREDENTIAL_PASSWORD_your_id_here=''
export DOCKER_AUTH_FILE_PULL=''
