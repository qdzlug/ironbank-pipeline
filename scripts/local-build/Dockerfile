# The IB pipeline automatically injects these args to enable these environment variables inside the pipeline
ARG http_proxy
ARG GOPROXY
ARG GOSUMDB

# TODO: test with a registry1.dso.mil image
# FROM busybox
FROM registry1.dso.mil/ironbank/redhat/ubi/ubi8:8.6
RUN cat /etc/yum.repos.d/ubi.repo \
    && dnf install -y wget
