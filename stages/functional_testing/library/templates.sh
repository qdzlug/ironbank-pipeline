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


package_auth_setup() {
  #  mkdir -p /root/.docker
   mkdir -p ~/.docker
   jq -n '{"auths": {"registry.dso.mil": {"auth": $bb_registry_auth}, "registry1.dso.mil": {"auth": $registry1_auth}, "registry.il2.dso.mil": {"auth": $il2_registry_auth}, "docker.io": {"auth": $bb_docker_auth} } }' \
     --arg bb_registry_auth ${BB_REGISTRY_AUTH} \
     --arg registry1_auth ${REGISTRY1_AUTH} \
     --arg il2_registry_auth ${IL2_REGISTRY_AUTH} \
     --arg bb_docker_auth ${DOCKER_AUTH} > ~/.docker/config.json
}


function setup_k8s_resources() {
    local NAMESPACE=$1

    # Ensure Docker credentials are set in environment variables
    if [[ -z "$DOCKER_USER" || -z "$DOCKER_PASSWORD" || -z "$DOCKER_REGISTRY_SERVER" ]]; then
        echo "Please set DOCKER_USER, DOCKER_REGISTRY_SERVER and DOCKER_PASSWORD environment variables."
        return 1
    fi

    # Create namespace if it doesn't exist
    # kubectl get ns $NAMESPACE || kubectl create ns $NAMESPACE #creating manually
    # kubectl delete secret my-registry-secret -n $NAMESPACE
    # Create Docker registry secret
    # kubectl get secret my-registry-secret -n $NAMESPACE || kubectl -n $NAMESPACE create secret docker-registry my-registry-secret \
    # --docker-server=$DOCKER_REGISTRY_SERVER \
    # --docker-username=$DOCKER_USER \
    # --docker-password=$DOCKER_PASSWORD
    # echo "$DOCKER_AUTH_FILE_PRE_PUBLISH" > /tmp/.dockerconfig.json

    kubectl get secret my-registry-secret -n $NAMESPACE || kubectl -n $NAMESPACE create secret generic my-registry-secret --type=kubernetes.io/dockerconfigjson --from-literal=.dockerconfigjson="$DOCKER_AUTH_FILE_PRE_PUBLISH"

#     # Create Role for patching service accounts # created manually
#     kubectl -n $NAMESPACE apply -f - <<EOF
# apiVersion: rbac.authorization.k8s.io/v1
# kind: Role
# metadata:
#   name: serviceaccount-patcher
# rules:
# - apiGroups: [""]
#   resources: ["*"]
#   verbs: ["*"]
# EOF

#     # Create RoleBinding to bind the Role to the service account
#     kubectl -n $NAMESPACE apply -f - <<EOF
# apiVersion: rbac.authorization.k8s.io/v1
# kind: RoleBinding
# metadata:
#   name: serviceaccount-patcher-binding
# subjects:
# - kind: ServiceAccount
#   name: default
#   namespace: gitlab
# roleRef:
#   kind: Role
#   name: serviceaccount-patcher
#   apiGroup: rbac.authorization.k8s.io
# EOF


    # Create and Patch service account if it hasn't been patched
    kubectl get serviceaccount testpod-sa -n $NAMESPACE || kubectl create serviceaccount testpod-sa -n $NAMESPACE

    if ! kubectl get serviceaccount testpod-sa -n $NAMESPACE -o=jsonpath='{.imagePullSecrets[?(@.name=="my-registry-secret")].name}' | grep -q "my-registry-secret"; then
        kubectl patch serviceaccount testpod-sa  -n $NAMESPACE -p '{"imagePullSecrets": [{"name": "my-registry-secret"}]}'
    fi

    # # Create resource quota if it doesn't exist and the namespace is not "command-probe-testing"
    # if [[ "$NAMESPACE" != "command-probe-testing" ]]; then
    #     if ! kubectl get resourcequota my-resource-quota -n $NAMESPACE; then
    #         kubectl create -n $NAMESPACE resourcequota my-resource-quota \
    #         --hard=pods=10,requests.cpu=1,requests.memory=1Gi,limits.cpu=2,limits.memory=2Gi
    #     fi
    # fi
}
