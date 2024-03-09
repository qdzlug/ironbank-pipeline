#!/bin/sh
#
#-----------------------------------------------------------------------------------------------------------------------
#
# Shell environment settings for verbosity and debugging
#
#-----------------------------------------------------------------------------------------------------------------------

# prevent it from being run standalone, which would do nothing
if [[ $BASH_SOURCE == $0 ]]; then
  echo "$0 is used to set env variables in the current shell and must be sourced to work"
  echo "examples: . $0"
  echo "          source $0"
  exit 1
fi

if [[ $DEBUG_ENABLED == "true" || "$CI_MERGE_REQUEST_TITLE" == *"DEBUG"*  || ${CI_MERGE_REQUEST_LABELS} == *"debug"* ]]; then
  echo "DEBUG_ENABLED is set to true, setting -x in bash"
  DEBUG="true"
  set -x
fi

trap 'echo ❌ exit at ${0}:${LINENO}, command was: ${BASH_COMMAND} 1>&2' ERR

package_auth_setup () {
  mkdir -p ~/.docker
  cp $DOCKER_AUTH_FILE_PRE_PUBLISH ~/.docker/config.json
}


function setup_k8s_resources() {
    local NAMESPACE=$1
    # Create namespace if it doesn't exist
    kubectl get ns $NAMESPACE || kubectl create ns $NAMESPACE 
    # Create secret if it doesn't exist
    kubectl get secret my-registry-secret -n $NAMESPACE || kubectl -n $NAMESPACE create secret generic my-registry-secret --type=kubernetes.io/dockerconfigjson --from-file=.dockerconfigjson=$DOCKER_AUTH_FILE_PRE_PUBLISH

    # Create and Patch service account if it hasn't been patched
    kubectl get serviceaccount testpod-sa -n $NAMESPACE || kubectl create serviceaccount testpod-sa -n $NAMESPACE

    if ! kubectl get serviceaccount testpod-sa -n $NAMESPACE -o=jsonpath='{.imagePullSecrets[?(@.name=="my-registry-secret")].name}' | grep -q "my-registry-secret"; then
        kubectl patch serviceaccount testpod-sa  -n $NAMESPACE -p '{"imagePullSecrets": [{"name": "my-registry-secret"}]}'
    fi
}
