#!/bin/bash

set -exv

NGINX_IMAGE="quay.io/cloudservices/turnpike-nginx"
WEB_IMAGE="quay.io/cloudservices/turnpike-web"
NGINX_PROMETHEUS_IMAGE="quay.io/cloudservices/turnpike-nginx-prometheus"
IMAGE_TAG=$(git rev-parse --short=7 HEAD)

if [[ -z "$QUAY_USER" || -z "$QUAY_TOKEN" ]]; then
    echo "QUAY_USER and QUAY_TOKEN must be set"
    exit 1
fi

# Create tmp dir to store data in during job run (do NOT store in $WORKSPACE)
export TMP_JOB_DIR=$(mktemp -d -p "$HOME" -t "jenkins-${JOB_NAME}-${BUILD_NUMBER}-XXXXXX")
echo "job tmp dir location: $TMP_JOB_DIR"

function job_cleanup() {
    echo "cleaning up job tmp dir: $TMP_JOB_DIR"
    rm -fr $TMP_JOB_DIR
}

trap job_cleanup EXIT ERR SIGINT SIGTERM

AUTH_CONF_DIR="$TMP_JOB_DIR/.podman"

mkdir -p $AUTH_CONF_DIR

podman login -u="$QUAY_USER" -p="$QUAY_TOKEN" quay.io

podman build -t "${NGINX_IMAGE}:${IMAGE_TAG}" nginx
podman push "${NGINX_IMAGE}:${IMAGE_TAG}"

podman build -t "${WEB_IMAGE}:${IMAGE_TAG}" .
podman push "${WEB_IMAGE}:${IMAGE_TAG}"

podman build \
       -f ./nginx/Dockerfile-prometheus \
       -t "${NGINX_PROMETHEUS_IMAGE}:${IMAGE_TAG}" .
podman push "${NGINX_PROMETHEUS_IMAGE}:${IMAGE_TAG}"
