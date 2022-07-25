set -euo pipefail

# Use either docker or rootful podman
# alias docker="sudo podman"
# docker() {
#     echo
#     echo "+" sudo podman "$@"
#     sudo podman "$@"
# }

cleanup() {
    ! docker logs proxy
    ! docker rm -f proxy
    ! docker network rm proxy-network
}
trap cleanup EXIT

# --internal creates a network without internet egress
docker network create --driver=bridge proxy-network --internal --subnet=172.19.0.0/24

docker create \
  --name proxy \
  -e ENVOY_UID=0 \
  -v "${PWD}/envoy.yaml:/etc/envoy/envoy.yaml:ro" \
  -v "${PWD}/replaceHttpsToHttpForRedirect.lua:/etc/envoy/scripts/replaceHttpsToHttpForRedirect.lua:ro" \
  -p 10000:10000 \
  envoyproxy/envoy-dev:ce49c7f65668a22b80d1e83c35d170741bb8d46a
# connect the private proxy network
# Note: this does not work with rootless podman:
#    Error: "slirp4netns" is not supported: invalid network mode
docker network connect --ip 172.19.0.100 proxy-network proxy
docker start proxy
sleep 10

# This works!
! docker run --rm -it \
    --network=proxy-network \
    -e http_proxy="http://172.19.0.100:10000" \
    curlimages/curl \
        http://example.com/

# Buildah is a little dumb: it still does a DNS resolution even if it uses a proxy to pull images
# Add registries to DNS with add-host and a nonsense 127.0.0.1 address
! docker run --rm -it \
    --network=proxy-network \
    --add-host=registry-1.docker.io:10.0.0.1 \
    --add-host=auth.docker.io:10.0.0.2 \
    -e BUILDAH_ISOLATION=chroot \
    -e http_proxy="http://172.19.0.100:10000" \
    -e HTTP_PROXY="http://172.19.0.100:10000" \
    -e https_proxy="http://172.19.0.100:10000" \
    -e HTTPS_PROXY="http://172.19.0.100:10000" \
    --security-opt=seccomp=unconfined \
    --workdir /workspace \
    --privileged \
    -v "${PWD}:/workspace:ro" \
    -v "${PWD}/registries.conf:/etc/containers/registries.conf:ro" \
    -v "${HOME}/.docker/:/root/.docker/:ro" \
    -v "${PWD}/dnf/mounts.conf:/root/.config/containers/mounts.conf:ro" \
    -v "${PWD}/dnf/:/root/dnf/:ro" \
    quay.io/buildah/stable:v1.23.3 buildah \
            --default-mounts-file=/root/.config/containers/mounts.conf \
            --storage-driver=vfs \
            --build-arg=http_proxy="http://172.19.0.100:10000" \
            --build-arg=GOPROXY="proxy.golang.org" \
            --build-arg=GOSUMDB="sum.golang.org" \
            bud -f Dockerfile

sleep 5
