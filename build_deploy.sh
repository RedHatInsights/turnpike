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

AUTH_CONF_DIR="$(pwd)/.podman"
mkdir -p $AUTH_CONF_DIR
export REGISTRY_AUTH_FILE="$AUTH_CONF_DIR/auth.json"

podman login -u="$QUAY_USER" -p="$QUAY_TOKEN" quay.io

podman build -t "${NGINX_IMAGE}:${IMAGE_TAG}" nginx
podman push "${NGINX_IMAGE}:${IMAGE_TAG}"

podman build -t "${WEB_IMAGE}:${IMAGE_TAG}" .
podman push "${WEB_IMAGE}:${IMAGE_TAG}"

podman build \
       --build-arg scrapeuri=http://nginx:8888/stub_status \
       -f ./nginx/Dockerfile-prometheus \
       -t "${NGINX_PROMETHEUS_IMAGE}:${IMAGE_TAG}" .
podman push "${NGINX_PROMETHEUS_IMAGE}:${IMAGE_TAG}"
